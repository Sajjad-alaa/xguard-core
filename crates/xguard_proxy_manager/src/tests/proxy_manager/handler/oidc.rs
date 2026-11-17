//! Sign-in with the external OpenID provider through Edge, over the real bidi stream and against
//! a mock provider that checks PKCE: the enrollment portal, the OpenID step of VPN MFA (legacy
//! and multi-step) and the OpenID authorization of MFA configuration.

use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio::time::timeout;
use tonic::Code;
use xguard_common::db::{
    Id,
    models::{
        User, vpn_client_mfa_session::VpnClientMfaSession, vpn_client_session::VpnClientMfaMethod,
    },
};
use xguard_core::{
    db::models::enrollment::{ENROLLMENT_TOKEN_TYPE, Token},
    events::{BidiStreamEventType, DesktopClientMfaEvent},
    sso::provider::{ProviderConfig, ProviderInput, ProviderKind},
};
use xguard_proto::{
    client_types::{
        AuthFlowType, AuthInfoRequest, MfaFlowStartRequest, MfaFlowStepFinishRequest, MfaMethod,
        OpenIdProviderKind, mfa_flow_start_response, mfa_step_result,
    },
    proxy::{
        AuthCallbackRequest, AuthInfoResponse, ClientMfaOidcAuthenticateRequest, CoreErrorCode,
        CoreRequest, CoreResponse, core_request, core_response,
    },
};

use super::support::{
    assert_error_response, assert_error_response_full, assert_vpn_session_exists,
    complete_proxy_handshake, create_mfa_network_with_methods, create_polling_token, create_user,
    create_user_with_device, expect_bidi_mfa_success, make_device_info, send_mfa_config_authorize,
    send_mfa_config_start, send_mfa_finish, send_mfa_finish_raw, send_mfa_start,
};
use crate::tests::common::{HandlerTestContext, MockIdentity, MockOidcProvider, RECEIVE_TIMEOUT};

const EDGE: &str = "http://localhost:8080";

fn next_id() -> u64 {
    static ID: AtomicU64 = AtomicU64::new(70_000);
    ID.fetch_add(1, Ordering::Relaxed)
}

async fn create_provider(pool: &PgPool, mock: &MockOidcProvider) {
    let mut conn = pool.acquire().await.unwrap();
    ProviderConfig::save(
        &mut conn,
        ProviderInput {
            kind: ProviderKind::Custom,
            issuer: mock.base_url.clone(),
            client_id: mock.client_id.clone(),
            client_secret: Some(mock.client_secret.clone()),
            enabled: true,
            display_name: Some("Test IdP".into()),
            disable_password_management: false,
        },
    )
    .await
    .expect("failed to save the OpenID provider");
}

async fn link(pool: &PgPool, user: &mut User<Id>, sub: &str) {
    user.openid_sub = Some(sub.to_owned());
    user.save(pool).await.expect("failed to link the user");
}

async fn request(context: &mut HandlerTestContext, payload: core_request::Payload) -> CoreResponse {
    let id = next_id();
    context.mock_proxy().send_request(CoreRequest {
        id,
        device_info: Some(make_device_info()),
        payload: Some(payload),
    });
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert_eq!(response.id, id);
    response
}

async fn auth_info_raw(
    context: &mut HandlerTestContext,
    flow: AuthFlowType,
    state: Option<&str>,
) -> CoreResponse {
    request(
        context,
        core_request::Payload::AuthInfo(AuthInfoRequest {
            state: state.map(str::to_owned),
            auth_flow_type: flow as i32,
            ..Default::default()
        }),
    )
    .await
}

async fn auth_info(
    context: &mut HandlerTestContext,
    flow: AuthFlowType,
    state: Option<&str>,
) -> AuthInfoResponse {
    match auth_info_raw(context, flow, state).await.payload {
        Some(core_response::Payload::AuthInfo(info)) => info,
        Some(core_response::Payload::CoreError(err)) => {
            panic!("AuthInfo failed: {} {}", err.status_code, err.message)
        }
        other => panic!("expected AuthInfo, got {}", describe(other.as_ref())),
    }
}

async fn enrollment_callback(
    context: &mut HandlerTestContext,
    code: &str,
    binding: &str,
) -> CoreResponse {
    request(
        context,
        core_request::Payload::AuthCallback(AuthCallbackRequest {
            code: code.to_owned(),
            nonce: binding.to_owned(),
        }),
    )
    .await
}

async fn mfa_callback(
    context: &mut HandlerTestContext,
    code: &str,
    state: &str,
    binding: &str,
) -> CoreResponse {
    request(
        context,
        core_request::Payload::ClientMfaOidcAuthenticate(ClientMfaOidcAuthenticateRequest {
            code: code.to_owned(),
            state: state.to_owned(),
            nonce: binding.to_owned(),
        }),
    )
    .await
}

/// Signs `identity` in for an MFA step referenced by `state` and returns Core's answer.
async fn complete_mfa_sign_in(
    context: &mut HandlerTestContext,
    mock: &MockOidcProvider,
    state: &str,
    identity: &MockIdentity,
) -> CoreResponse {
    let info = auth_info(context, AuthFlowType::Mfa, Some(state)).await;
    let (code, returned_state) = mock.sign_in(&info.url, identity);
    assert_eq!(returned_state, info.csrf_token);
    mfa_callback(context, &code, &returned_state, &info.nonce).await
}

/// `Payload` has no `Debug`, since some variants carry secrets.
fn describe(payload: Option<&core_response::Payload>) -> String {
    match payload {
        Some(core_response::Payload::CoreError(err)) => {
            format!("CoreError {} {}", err.status_code, err.message)
        }
        Some(other) => format!("{:?}", std::mem::discriminant(other)),
        None => "no payload".into(),
    }
}

fn assert_empty(response: &CoreResponse) {
    match &response.payload {
        Some(core_response::Payload::Empty(())) => {}
        Some(core_response::Payload::CoreError(err)) => {
            panic!("expected Empty, got {} {}", err.status_code, err.message)
        }
        other => panic!("expected Empty, got {}", describe(other.as_ref())),
    }
}

#[sqlx::test]
async fn test_auth_info_requires_enabled_provider(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;

    let response = auth_info_raw(&mut context, AuthFlowType::Enrollment, None).await;
    assert_eq!(assert_error_response(&response), Code::NotFound);
    // Pre-2.0 clients without a flow type are refused.
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let response = auth_info_raw(&mut context, AuthFlowType::Unspecified, None).await;
    assert_eq!(assert_error_response(&response), Code::InvalidArgument);

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_auth_info_enrollment_builds_pkce_url_on_edge(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;

    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let url = reqwest::Url::parse(&info.url).unwrap();
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    assert!(
        info.url
            .starts_with(&format!("{}/authorize?", mock.base_url))
    );
    assert_eq!(
        param("redirect_uri").as_deref(),
        Some(format!("{EDGE}/openid/callback").as_str())
    );
    assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(param("state").as_deref(), Some(info.csrf_token.as_str()));
    // The binding Edge keeps in its cookie is never sent to the provider.
    assert!(!info.nonce.is_empty());
    assert!(!info.url.contains(&info.nonce));
    assert_ne!(param("nonce").as_deref(), Some(info.nonce.as_str()));
    assert_eq!(info.button_display_name.as_deref(), Some("Test IdP"));
    assert_eq!(info.provider_kind(), OpenIdProviderKind::Custom);

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_enrollment_sign_in_creates_account_and_starts_enrollment(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;

    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let identity = MockIdentity::new("new-sub", "new.person@example.org");
    let (code, _) = mock.sign_in(&info.url, &identity);
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    let Some(core_response::Payload::AuthCallback(callback)) = response.payload else {
        panic!(
            "expected AuthCallback, got {}",
            describe(response.payload.as_ref())
        );
    };
    assert_eq!(callback.url.trim_end_matches('/'), EDGE);

    let token = Token::find_by_id(&context.pool, &callback.token)
        .await
        .unwrap();
    assert_eq!(token.token_type.as_deref(), Some(ENROLLMENT_TOKEN_TYPE));
    let user = User::find_by_id(&context.pool, token.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.email, "new.person@example.org");
    assert_eq!(user.openid_sub.as_deref(), Some("new-sub"));
    assert!(!user.has_password());

    // The desktop client configured with this token sees OpenID as available. (Built directly:
    // the enrollment start page depends on global welcome-message settings that parallel tests
    // reset.)
    let settings = xguard_common::db::models::Settings::get_current_settings();
    let instance = xguard_proto::client_types::InstanceInfo::from(
        xguard_core::grpc::InstanceInfo::build(&context.pool, &settings, &user, None)
            .await
            .unwrap(),
    );
    assert_eq!(instance.openid_available, Some(true));
    assert_eq!(instance.openid_display_name.as_deref(), Some("Test IdP"));
    assert!(
        instance
            .mfa_capabilities
            .unwrap()
            .authorize_methods
            .contains(&(MfaMethod::Oidc as i32))
    );

    // The sign-in cannot be replayed.
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    assert_eq!(assert_error_response(&response), Code::Unauthenticated);

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_enrollment_sign_in_follows_linking_rules(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let existing = create_user(&context.pool).await;

    // An unverified email neither links the existing account nor creates one.
    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let mut identity = MockIdentity::new("sub-a", &existing.email);
    identity.email_verified = Some(false);
    let (code, _) = mock.sign_in(&info.url, &identity);
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    assert_eq!(assert_error_response(&response), Code::PermissionDenied);
    let reloaded = User::find_by_id(&context.pool, existing.id)
        .await
        .unwrap()
        .unwrap();
    assert!(reloaded.openid_sub.is_none());

    // A verified email links it, and an older unused enrollment token stops working.
    let old = Token::new(
        existing.id,
        None,
        None,
        3600,
        Some(ENROLLMENT_TOKEN_TYPE.to_owned()),
    );
    old.save(&context.pool).await.unwrap();
    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let (code, _) = mock.sign_in(&info.url, &MockIdentity::new("sub-a", &existing.email));
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    let Some(core_response::Payload::AuthCallback(callback)) = response.payload else {
        panic!(
            "expected AuthCallback, got {}",
            describe(response.payload.as_ref())
        );
    };
    let token = Token::find_by_id(&context.pool, &callback.token)
        .await
        .unwrap();
    assert_eq!(token.user_id, existing.id);
    assert!(Token::find_by_id(&context.pool, &old.id).await.is_err());
    let reloaded = User::find_by_id(&context.pool, existing.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.openid_sub.as_deref(), Some("sub-a"));

    // Another identity with the same email cannot take the account over.
    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let (code, _) = mock.sign_in(&info.url, &MockIdentity::new("sub-b", &existing.email));
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    assert_eq!(assert_error_response(&response), Code::PermissionDenied);

    // A disabled account cannot enroll.
    let mut disabled = reloaded;
    disabled.is_active = false;
    disabled.save(&context.pool).await.unwrap();
    let info = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let (code, _) = mock.sign_in(&info.url, &MockIdentity::new("sub-a", &existing.email));
    let response = enrollment_callback(&mut context, &code, &info.nonce).await;
    assert_eq!(assert_error_response(&response), Code::PermissionDenied);

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_enrollment_code_from_another_sign_in_is_refused(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;

    // An attacker's code injected into the victim's sign-in fails PKCE at the provider.
    let attacker = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let victim = auth_info(&mut context, AuthFlowType::Enrollment, None).await;
    let (code, _) = mock.sign_in(&attacker.url, &MockIdentity::new("sub-x", "x@example.org"));
    let response = enrollment_callback(&mut context, &code, &victim.nonce).await;
    let (status, _, error_code) = assert_error_response_full(&response);
    assert_eq!(status, Code::Unauthenticated);
    assert_eq!(error_code, CoreErrorCode::OidcVerificationFailed);

    // An unknown binding is refused before anything reaches the provider.
    let response = enrollment_callback(&mut context, &code, &"z".repeat(40)).await;
    assert_eq!(assert_error_response(&response), Code::Unauthenticated);
    // The victim's sign-in was used up by the failed attempt.
    let response = enrollment_callback(&mut context, &code, &victim.nonce).await;
    let (status, _, error_code) = assert_error_response_full(&response);
    assert_eq!(status, Code::Unauthenticated);
    assert_eq!(error_code, CoreErrorCode::Unspecified);

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_legacy_mfa_with_openid(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let network =
        create_mfa_network_with_methods(&context.pool, vec![VpnClientMfaMethod::Oidc]).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    link(&context.pool, &mut user, "owner-sub").await;

    let (_, token) = send_mfa_start(
        &mut context,
        network.id,
        &device.wireguard_pubkey,
        MfaMethod::Oidc,
    )
    .await;
    // Polling before the browser sign-in is not a failure.
    let response = send_mfa_finish_raw(&mut context, &token, None).await;
    let (status, message, _) = assert_error_response_full(&response);
    assert_eq!(status, Code::FailedPrecondition);
    assert!(message.starts_with("OIDC authentication not completed"));

    let response = complete_mfa_sign_in(
        &mut context,
        &mock,
        &token,
        &MockIdentity::new("owner-sub", &user.email),
    )
    .await;
    assert_empty(&response);

    let (_, psk) = send_mfa_finish(&mut context, &token, None).await;
    assert!(!psk.is_empty());
    assert_vpn_session_exists(&context.pool, network.id, device.id).await;
    assert_eq!(
        expect_bidi_mfa_success(&mut context.bidi_events_rx).await,
        network.id
    );

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_multi_step_mfa_with_openid_is_bound_to_the_attempt(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let network =
        create_mfa_network_with_methods(&context.pool, vec![VpnClientMfaMethod::Oidc]).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    link(&context.pool, &mut user, "owner-sub").await;

    let response = request(
        &mut context,
        core_request::Payload::MfaFlowStart(MfaFlowStartRequest {
            location_id: network.id,
            pubkey: device.wireguard_pubkey.clone(),
            selected_methods: vec![MfaMethod::Oidc as i32],
        }),
    )
    .await;
    let Some(core_response::Payload::MfaFlowStart(started)) = response.payload else {
        panic!(
            "expected MfaFlowStart, got {}",
            describe(response.payload.as_ref())
        );
    };
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = started.outcome else {
        panic!("expected an accepted plan");
    };
    let token = accepted.token;
    let attempt = accepted.first_step.unwrap().step_attempt_id;

    // A multi-step session must name its attempt, and only the current one.
    for state in [token.clone(), format!("{token}.{}", "a".repeat(32))] {
        let response = auth_info_raw(&mut context, AuthFlowType::Mfa, Some(&state)).await;
        let (status, _, error_code) = assert_error_response_full(&response);
        assert_eq!(status, Code::Unauthenticated);
        assert_eq!(error_code, CoreErrorCode::MfaSessionExpired);
    }
    let response = auth_info_raw(&mut context, AuthFlowType::Mfa, Some("not a token")).await;
    assert_eq!(assert_error_response(&response), Code::InvalidArgument);

    let state = format!("{token}.{attempt}");
    let finish = |context: &mut HandlerTestContext| {
        let token = token.clone();
        let attempt = attempt.clone();
        let id = next_id();
        context.mock_proxy().send_request(CoreRequest {
            id,
            device_info: Some(make_device_info()),
            payload: Some(core_request::Payload::MfaFlowStepFinish(
                MfaFlowStepFinishRequest {
                    token,
                    step_attempt_id: attempt,
                    submission: None,
                },
            )),
        });
    };
    finish(&mut context);
    let response = context.mock_proxy_mut().recv_outbound().await;
    let Some(core_response::Payload::MfaFlowStepFinish(result)) = response.payload else {
        panic!(
            "expected MfaFlowStepFinish, got {}",
            describe(response.payload.as_ref())
        );
    };
    assert!(matches!(
        result.result.unwrap().outcome,
        Some(mfa_step_result::Outcome::AwaitingExternal(_))
    ));

    // The state Edge forwards must match the one Core issued.
    let info = auth_info(&mut context, AuthFlowType::Mfa, Some(&state)).await;
    let (code, _) = mock.sign_in(&info.url, &MockIdentity::new("owner-sub", &user.email));
    let response = mfa_callback(&mut context, &code, "forged-state", &info.nonce).await;
    let (status, _, error_code) = assert_error_response_full(&response);
    assert_eq!(status, Code::Unauthenticated);
    assert_eq!(error_code, CoreErrorCode::MfaSessionExpired);

    let response = complete_mfa_sign_in(
        &mut context,
        &mock,
        &state,
        &MockIdentity::new("owner-sub", &user.email),
    )
    .await;
    assert_empty(&response);

    finish(&mut context);
    let response = context.mock_proxy_mut().recv_outbound().await;
    let Some(core_response::Payload::MfaFlowStepFinish(result)) = response.payload else {
        panic!(
            "expected MfaFlowStepFinish, got {}",
            describe(response.payload.as_ref())
        );
    };
    let Some(mfa_step_result::Outcome::Completed(completed)) = result.result.unwrap().outcome
    else {
        panic!("expected the flow to complete");
    };
    assert!(!completed.preshared_key.is_empty());
    assert_vpn_session_exists(&context.pool, network.id, device.id).await;

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_mfa_with_another_identity_ends_the_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let network =
        create_mfa_network_with_methods(&context.pool, vec![VpnClientMfaMethod::Oidc]).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    link(&context.pool, &mut user, "owner-sub").await;
    let mut other = create_user(&context.pool).await;
    link(&context.pool, &mut other, "other-sub").await;

    let (_, token) = send_mfa_start(
        &mut context,
        network.id,
        &device.wireguard_pubkey,
        MfaMethod::Oidc,
    )
    .await;
    let response = complete_mfa_sign_in(
        &mut context,
        &mock,
        &token,
        &MockIdentity::new("other-sub", &other.email),
    )
    .await;
    let (status, message, error_code) = assert_error_response_full(&response);
    assert_eq!(status, Code::Unauthenticated);
    assert_eq!(message, "unauthorized");
    assert_eq!(error_code, CoreErrorCode::OidcAccountMismatch);
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&context.pool, &token)
            .await
            .unwrap()
            .is_none(),
        "a sign-in as another identity must end the MFA session"
    );
    // The failure is audited, and no account was linked or changed.
    let event = timeout(RECEIVE_TIMEOUT, context.bidi_events_rx.recv())
        .await
        .expect("no audit event")
        .expect("event channel closed");
    let BidiStreamEventType::DesktopClientMfa(event) = event.event else {
        panic!("expected a VPN client MFA event");
    };
    assert!(matches!(
        *event,
        DesktopClientMfaEvent::Failed {
            method: MfaMethod::Oidc,
            ..
        }
    ));
    let reloaded = User::find_by_id(&context.pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.openid_sub.as_deref(), Some("owner-sub"));

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_mfa_with_openid_requires_a_linked_account(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let network =
        create_mfa_network_with_methods(&context.pool, vec![VpnClientMfaMethod::Oidc]).await;
    let (_user, device) = create_user_with_device(&context.pool).await;

    let response = request(
        &mut context,
        core_request::Payload::ClientMfaStart(xguard_proto::client_types::ClientMfaStartRequest {
            location_id: network.id,
            pubkey: device.wireguard_pubkey.clone(),
            method: MfaMethod::Oidc as i32,
        }),
    )
    .await;
    assert!(matches!(
        response.payload,
        Some(core_response::Payload::CoreError(_))
    ));

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_mfa_configuration_authorized_with_openid(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mock = MockOidcProvider::start().await;
    create_provider(&context.pool, &mock).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    link(&context.pool, &mut user, "owner-sub").await;
    let polling_token = create_polling_token(&context.pool, device.id).await;

    let response =
        send_mfa_config_start(&mut context, &polling_token, &device.wireguard_pubkey).await;
    let Some(core_response::Payload::MfaConfigStart(started)) = response.payload else {
        panic!(
            "expected MfaConfigStart, got {}",
            describe(response.payload.as_ref())
        );
    };
    assert_eq!(started.available_methods, vec![MfaMethod::Oidc as i32]);
    assert!(!started.email_fallback);
    let session = started.session_token;

    // The client polls until the browser sign-in is done.
    let response = send_mfa_config_authorize(&mut context, &session, MfaMethod::Oidc, "").await;
    let (status, message, _) = assert_error_response_full(&response);
    assert_eq!(status, Code::FailedPrecondition);
    assert!(message.starts_with("OIDC authentication not completed"));

    // Another identity ends the session.
    let response = complete_mfa_sign_in(
        &mut context,
        &mock,
        &session,
        &MockIdentity::new("someone-else", "x@example.org"),
    )
    .await;
    let (_, _, error_code) = assert_error_response_full(&response);
    assert_eq!(error_code, CoreErrorCode::OidcAccountMismatch);
    assert!(Token::find_by_id(&context.pool, &session).await.is_err());

    let response =
        send_mfa_config_start(&mut context, &polling_token, &device.wireguard_pubkey).await;
    let Some(core_response::Payload::MfaConfigStart(started)) = response.payload else {
        panic!(
            "expected MfaConfigStart, got {}",
            describe(response.payload.as_ref())
        );
    };
    let session = started.session_token;
    let response = complete_mfa_sign_in(
        &mut context,
        &mock,
        &session,
        &MockIdentity::new("owner-sub", &user.email),
    )
    .await;
    assert_empty(&response);
    let response = send_mfa_config_authorize(&mut context, &session, MfaMethod::Oidc, "").await;
    assert!(
        matches!(
            response.payload,
            Some(core_response::Payload::MfaConfigAuthorize(_))
        ),
        "expected MfaConfigAuthorize, got {:?}",
        describe(response.payload.as_ref())
    );

    context.finish().await.expect_server_finished().await;
}
