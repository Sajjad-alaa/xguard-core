//! FIDO2 security keys over the real bidi stream: registration from an MFA configuration
//! session, authorizing a configuration session with a key, and VPN MFA with a key.
//! The key is the software P-256 authenticator from `xguard_core::fido2::test_authenticator`.

use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_common::db::{
    Id,
    models::{
        User, WebAuthn,
        settings::Settings,
        vpn_client_session::{VpnClientMfaMethod, VpnClientSession},
        webauthn::RegistrationSource,
    },
};
use xguard_core::{
    db::models::enrollment::Token,
    events::{ApiEventType, BidiStreamEventType, DesktopClientMfaEvent},
    fido2::{Fido2Assertion, test_authenticator::TestAuthenticator},
};
use xguard_proto::{
    client_types::{
        CodeMfaSetupFinishRequest, MfaConfigAuthorizeRequest, MfaConfigFido2ChallengeRequest,
        MfaFido2Assertion, MfaFlowStartRequest, MfaFlowStepFinishRequest, MfaMethod,
        mfa_flow_start_response, mfa_flow_step_finish_request, mfa_step_result, mfa_step_started,
    },
    proxy::{CoreRequest, CoreResponse, core_request, core_response},
};

use super::support::{
    assert_error_response, complete_proxy_handshake, create_multi_step_mfa_network_with_steps,
    create_polling_token, create_user_with_device, expect_bidi_mfa_success, generate_totp_code,
    make_device_info, send_code_mfa_setup_start, send_mfa_config_authorize, send_mfa_config_start,
    setup_user_totp_mfa,
};
use crate::tests::common::HandlerTestContext;

// The default XGuard URL of a fresh database. Settings are process-wide, so tests running in
// parallel keep agreeing on the relying party.
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8000";

static REQUEST_ID: AtomicU64 = AtomicU64::new(60_000);

fn next_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// The error a response carries, for assertion messages (payloads are not `Debug`).
fn describe(payload: Option<&core_response::Payload>) -> String {
    match payload {
        Some(core_response::Payload::CoreError(err)) => {
            format!("error {}: {}", err.status_code, err.message)
        }
        Some(_) => "another response".to_owned(),
        None => "no payload".to_owned(),
    }
}

async fn send(context: &mut HandlerTestContext, payload: core_request::Payload) -> CoreResponse {
    context.mock_proxy().send_request(CoreRequest {
        id: next_id(),
        device_info: Some(make_device_info()),
        payload: Some(payload),
    });
    context.mock_proxy_mut().recv_outbound().await
}

/// Keys are bound to the default XGuard URL of a fresh database; settings are not changed, as
/// they are shared by tests running in parallel.
async fn set_xguard_url(_context: &HandlerTestContext) {
    assert_eq!(
        Settings::get_current_settings()
            .xguard_url
            .trim_end_matches('/'),
        ORIGIN
    );
}

/// Starts an MFA configuration session for a TOTP user and authorizes it with a TOTP code.
async fn authorized_session(context: &mut HandlerTestContext) -> (String, User<Id>, String) {
    let (mut user, device) = create_user_with_device(&context.pool).await;
    setup_user_totp_mfa(&context.pool, &mut user).await;
    let polling_token = create_polling_token(&context.pool, device.id).await;
    let session_token =
        start_config_session(context, &polling_token, &device.wireguard_pubkey).await;
    let authorized = send_mfa_config_authorize(
        context,
        &session_token,
        MfaMethod::Totp,
        &generate_totp_code(&user),
    )
    .await;
    assert!(matches!(
        authorized.payload,
        Some(core_response::Payload::MfaConfigAuthorize(_))
    ));
    (session_token, user, device.wireguard_pubkey)
}

async fn start_config_session(
    context: &mut HandlerTestContext,
    polling_token: &str,
    pubkey: &str,
) -> String {
    let start = send_mfa_config_start(context, polling_token, pubkey).await;
    match start.payload {
        Some(core_response::Payload::MfaConfigStart(response)) => response.session_token,
        _ => panic!("expected MfaConfigStartResponse"),
    }
}

async fn fido2_setup_start(context: &mut HandlerTestContext, session_token: &str) -> String {
    let response = send_code_mfa_setup_start(context, session_token, MfaMethod::Fido2).await;
    match response.payload {
        Some(core_response::Payload::CodeMfaSetupStartResponse(response)) => {
            assert!(response.totp_secret.is_none());
            response
                .fido2_creation_challenge
                .expect("FIDO2 setup must return creation options")
        }
        other => panic!(
            "expected CodeMfaSetupStartResponse, got {}",
            describe(other.as_ref())
        ),
    }
}

async fn fido2_setup_finish(
    context: &mut HandlerTestContext,
    session_token: &str,
    name: Option<&str>,
    attestation: Option<String>,
) -> CoreResponse {
    send(
        context,
        core_request::Payload::CodeMfaSetupFinish(CodeMfaSetupFinishRequest {
            code: String::new(),
            token: session_token.to_owned(),
            method: MfaMethod::Fido2 as i32,
            name: name.map(str::to_owned),
            fido2_attestation: attestation,
        }),
    )
    .await
}

/// Registers `key` from an authorized configuration session.
async fn register_key(
    context: &mut HandlerTestContext,
    session_token: &str,
    key: &mut TestAuthenticator,
) {
    let options = fido2_setup_start(context, session_token).await;
    let response = fido2_setup_finish(
        context,
        session_token,
        Some("YubiKey"),
        Some(key.register(&options, ORIGIN)),
    )
    .await;
    assert!(
        matches!(
            response.payload,
            Some(core_response::Payload::CodeMfaSetupFinishResponse(_))
        ),
        "FIDO2 setup must finish: {}",
        describe(response.payload.as_ref())
    );
}

#[sqlx::test]
async fn test_fido2_setup_registers_a_vpn_security_key(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    set_xguard_url(&context).await;
    let (session_token, user, _) = authorized_session(&mut context).await;

    let mut key = TestAuthenticator::new();
    let options = fido2_setup_start(&mut context, &session_token).await;
    let token = Token::find_by_id(&context.pool, &session_token)
        .await
        .unwrap();
    assert!(
        token.mfa_setup_state.is_some(),
        "the ceremony state is kept"
    );
    let response = fido2_setup_finish(
        &mut context,
        &session_token,
        Some("  YubiKey  "),
        Some(key.register(&options, ORIGIN)),
    )
    .await;
    assert!(matches!(
        response.payload,
        Some(core_response::Payload::CodeMfaSetupFinishResponse(_))
    ));

    let keys = WebAuthn::all_for_user(&context.pool, user.id)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "YubiKey");
    assert_eq!(keys[0].registration_source, RegistrationSource::Desktop);
    assert_eq!(
        WebAuthn::vpn_key_ids_for_user(&context.pool, user.id)
            .await
            .unwrap(),
        vec![keys[0].id]
    );
    let token = Token::find_by_id(&context.pool, &session_token)
        .await
        .unwrap();
    assert!(
        token.mfa_setup_state.is_none(),
        "the ceremony state is used up"
    );
    let user = User::find_by_id(&context.pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.mfa_enabled);

    let event = context
        .event_rx
        .try_recv()
        .expect("an event must be emitted");
    assert!(
        matches!(*event.event, ApiEventType::MfaSecurityKeyAdded { .. }),
        "expected MfaSecurityKeyAdded"
    );

    // The same key cannot be registered twice: it is excluded, and the old answer is used up.
    let response = fido2_setup_finish(
        &mut context,
        &session_token,
        Some("again"),
        Some(key.register(&options, ORIGIN)),
    )
    .await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::InvalidArgument
    );
    let options = fido2_setup_start(&mut context, &session_token).await;
    let options: serde_json::Value = serde_json::from_str(&options).unwrap();
    assert_eq!(
        options["publicKey"]["excludeCredentials"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_fido2_setup_refusals_save_nothing(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    set_xguard_url(&context).await;
    let (session_token, user, _) = authorized_session(&mut context).await;

    // Finish without a start.
    let response = fido2_setup_finish(
        &mut context,
        &session_token,
        Some("key"),
        Some("{\"not\":\"an attestation\"}".to_owned()),
    )
    .await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::InvalidArgument
    );

    // Missing name or response, a bad name, a synced passkey, a key without a PIN, an answer
    // for another origin.
    let mut key = TestAuthenticator::new();
    let options = fido2_setup_start(&mut context, &session_token).await;
    let attestation = key.register(&options, ORIGIN);
    for (name, attestation) in [
        (None, Some(attestation.clone())),
        (Some("key"), None),
        (Some("bad\u{7}name"), Some(attestation)),
    ] {
        let response = fido2_setup_finish(&mut context, &session_token, name, attestation).await;
        assert_eq!(
            assert_error_response(&response),
            tonic::Code::InvalidArgument
        );
    }
    let mut synced = TestAuthenticator::new();
    synced.backup_eligible = true;
    let mut no_pin = TestAuthenticator::new();
    no_pin.user_verified = false;
    for (mut authenticator, origin) in [
        (synced, ORIGIN),
        (no_pin, ORIGIN),
        (TestAuthenticator::new(), "https://evil.example.com"),
    ] {
        let options = fido2_setup_start(&mut context, &session_token).await;
        let response = fido2_setup_finish(
            &mut context,
            &session_token,
            Some("key"),
            Some(authenticator.register(&options, origin)),
        )
        .await;
        assert_eq!(
            assert_error_response(&response),
            tonic::Code::InvalidArgument
        );
        let token = Token::find_by_id(&context.pool, &session_token)
            .await
            .unwrap();
        assert!(
            token.mfa_setup_state.is_none(),
            "a refused answer uses the ceremony up"
        );
    }
    assert!(
        WebAuthn::all_for_user(&context.pool, user.id)
            .await
            .unwrap()
            .is_empty()
    );

    context.finish().await.expect_server_finished().await;
}

/// An unauthorized session cannot register a key.
#[sqlx::test]
async fn test_fido2_setup_requires_an_authorized_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    set_xguard_url(&context).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    setup_user_totp_mfa(&context.pool, &mut user).await;
    let polling_token = create_polling_token(&context.pool, device.id).await;
    let session_token =
        start_config_session(&mut context, &polling_token, &device.wireguard_pubkey).await;

    let response = send_code_mfa_setup_start(&mut context, &session_token, MfaMethod::Fido2).await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::Unauthenticated
    );

    context.finish().await.expect_server_finished().await;
}

fn assertion_request(session_token: &str, assertion: Fido2Assertion) -> MfaConfigAuthorizeRequest {
    MfaConfigAuthorizeRequest {
        session_token: session_token.to_owned(),
        method: MfaMethod::Fido2 as i32,
        code: String::new(),
        signature: Some(assertion.signature),
        auth_data: Some(assertion.authenticator_data),
        credential_id: Some(assertion.credential_id),
    }
}

async fn config_challenge(context: &mut HandlerTestContext, session_token: &str) -> String {
    let response = send(
        context,
        core_request::Payload::MfaConfigFido2Challenge(MfaConfigFido2ChallengeRequest {
            session_token: session_token.to_owned(),
        }),
    )
    .await;
    match response.payload {
        Some(core_response::Payload::MfaConfigFido2Challenge(response)) => {
            assert_eq!(response.credential_ids.len(), 1);
            response.challenge
        }
        other => panic!(
            "expected MfaConfigFido2ChallengeResponse, got {}",
            describe(other.as_ref())
        ),
    }
}

/// A registered key authorizes a later configuration session; each challenge answers once.
#[sqlx::test]
async fn test_fido2_authorizes_mfa_configuration(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    set_xguard_url(&context).await;
    let (session_token, user, pubkey) = authorized_session(&mut context).await;
    let mut key = TestAuthenticator::new();
    register_key(&mut context, &session_token, &mut key).await;
    let device = xguard_common::db::models::Device::find_by_pubkey(&context.pool, &pubkey)
        .await
        .unwrap()
        .unwrap();
    let polling_token = create_polling_token(&context.pool, device.id).await;
    let session_token = start_config_session(&mut context, &polling_token, &pubkey).await;

    // Without a challenge.
    let assertion = key.assert(RP_ID, "bm9uZQ", ORIGIN);
    let response = send(
        &mut context,
        core_request::Payload::MfaConfigAuthorize(assertion_request(&session_token, assertion)),
    )
    .await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::FailedPrecondition
    );

    // A wrong answer uses the challenge up.
    let challenge = config_challenge(&mut context, &session_token).await;
    let wrong = key.assert(RP_ID, &challenge, "https://evil.example.com");
    let response = send(
        &mut context,
        core_request::Payload::MfaConfigAuthorize(assertion_request(&session_token, wrong)),
    )
    .await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::Unauthenticated
    );
    let right = key.assert(RP_ID, &challenge, ORIGIN);
    let response = send(
        &mut context,
        core_request::Payload::MfaConfigAuthorize(assertion_request(&session_token, right)),
    )
    .await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::FailedPrecondition
    );

    let challenge = config_challenge(&mut context, &session_token).await;
    let right = key.assert(RP_ID, &challenge, ORIGIN);
    let response = send(
        &mut context,
        core_request::Payload::MfaConfigAuthorize(assertion_request(&session_token, right)),
    )
    .await;
    assert!(
        matches!(
            response.payload,
            Some(core_response::Payload::MfaConfigAuthorize(_))
        ),
        "a valid assertion must authorize: {}",
        describe(response.payload.as_ref())
    );
    let _ = user;

    context.finish().await.expect_server_finished().await;
}

async fn flow_start(
    context: &mut HandlerTestContext,
    location_id: Id,
    pubkey: &str,
) -> (String, String, String, Vec<String>) {
    let response = send(
        context,
        core_request::Payload::MfaFlowStart(MfaFlowStartRequest {
            posture: None,
            location_id,
            pubkey: pubkey.to_owned(),
            selected_methods: vec![MfaMethod::Fido2 as i32],
        }),
    )
    .await;
    let described = describe(response.payload.as_ref());
    let Some(core_response::Payload::MfaFlowStart(response)) = response.payload else {
        panic!("expected MfaFlowStart, got {described}");
    };
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("expected an accepted flow start");
    };
    let step = accepted.first_step.expect("first step");
    let Some(mfa_step_started::Challenge::Fido2(challenge)) = step.challenge else {
        panic!("expected a FIDO2 challenge");
    };
    (
        accepted.token,
        step.step_attempt_id,
        challenge.challenge,
        challenge.credential_ids,
    )
}

async fn flow_finish(
    context: &mut HandlerTestContext,
    token: &str,
    attempt_id: &str,
    assertion: Fido2Assertion,
) -> CoreResponse {
    send(
        context,
        core_request::Payload::MfaFlowStepFinish(MfaFlowStepFinishRequest {
            token: token.to_owned(),
            step_attempt_id: attempt_id.to_owned(),
            submission: Some(mfa_flow_step_finish_request::Submission::Fido2(
                MfaFido2Assertion {
                    rp_id_hash: assertion.rp_id_hash,
                    authenticator_data: assertion.authenticator_data,
                    signature: assertion.signature,
                    credential_id: assertion.credential_id,
                },
            )),
        }),
    )
    .await
}

/// VPN MFA with a security key over the 2.2 contract: a wrong answer is audited and uses the
/// challenge up, a fresh connection attempt with the right answer authorizes the peer.
#[sqlx::test]
async fn test_fido2_vpn_mfa(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    set_xguard_url(&context).await;
    // Created first, so the device created next joins it.
    let network = create_multi_step_mfa_network_with_steps(
        &context.pool,
        vec![vec![VpnClientMfaMethod::Fido2]],
    )
    .await;
    let (session_token, user, pubkey) = authorized_session(&mut context).await;
    let mut key = TestAuthenticator::new();
    register_key(&mut context, &session_token, &mut key).await;
    let device = xguard_common::db::models::Device::find_by_pubkey(&context.pool, &pubkey)
        .await
        .unwrap()
        .unwrap();
    while context.bidi_events_rx.try_recv().is_ok() {}

    let (token, attempt_id, challenge, credential_ids) =
        flow_start(&mut context, network.id, &pubkey).await;
    assert_eq!(credential_ids.len(), 1);

    let wrong = key.assert("evil.example.com", &challenge, ORIGIN);
    let response = flow_finish(&mut context, &token, &attempt_id, wrong).await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::Unauthenticated
    );
    let event = context.bidi_events_rx.try_recv().expect("a failure event");
    match event.event {
        BidiStreamEventType::DesktopClientMfa(event) => match *event {
            DesktopClientMfaEvent::Failed { method, .. } => {
                assert_eq!(method, VpnClientMfaMethod::Fido2.into());
            }
            other => panic!("unexpected event {other:?}"),
        },
        other => panic!("unexpected event {other:?}"),
    }
    let right = key.assert(RP_ID, &challenge, ORIGIN);
    let response = flow_finish(&mut context, &token, &attempt_id, right).await;
    assert_eq!(
        assert_error_response(&response),
        tonic::Code::InvalidArgument
    );

    let (token, attempt_id, challenge, _) = flow_start(&mut context, network.id, &pubkey).await;
    // The new attempt supersedes the failed one (`MfaLoginSuperseded`).
    while context.bidi_events_rx.try_recv().is_ok() {}
    let right = key.assert(RP_ID, &challenge, ORIGIN);
    let response = flow_finish(&mut context, &token, &attempt_id, right).await;
    let described = describe(response.payload.as_ref());
    let Some(core_response::Payload::MfaFlowStepFinish(result)) = response.payload else {
        panic!("expected MfaFlowStepFinish, got {described}");
    };
    assert!(matches!(
        result.result.and_then(|result| result.outcome),
        Some(mfa_step_result::Outcome::Completed(_))
    ));
    assert_eq!(
        expect_bidi_mfa_success(&mut context.bidi_events_rx).await,
        network.id
    );
    assert_eq!(
        VpnClientSession::get_all_active_device_sessions_in_location(
            &context.pool,
            network.id,
            device.id
        )
        .await
        .unwrap()
        .len(),
        1
    );
    let _ = user;

    context.finish().await.expect_server_finished().await;
}
