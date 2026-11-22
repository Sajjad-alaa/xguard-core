use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use ipnetwork::IpNetwork;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{sleep, timeout},
};
use tonic::Code;
use totp_lite::{Sha1, totp_custom};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, DeviceType, User, WireguardNetwork,
            biometric_auth::BiometricAuth,
            device::WireguardNetworkDevice,
            mfa_flow::{LocationMfaFlowAssignment, MfaFlow},
            settings::initialize_current_settings,
            user::{TOTP_CODE_DIGITS, TOTP_CODE_VALIDITY_PERIOD},
            vpn_client_mfa_session::{
                MFA_FAILED_ATTEMPT_CAP, MfaAttribution, VPN_MFA_SESSION_TIMEOUT,
                VpnClientMfaSession, VpnMfaFlowKind,
            },
            vpn_client_session::{VpnClientMfaMethod, VpnClientSession, VpnClientSessionState},
            wireguard::ServiceLocationMode,
        },
        setup_pool,
    },
    secret::SecretStringWrapper,
};
use xguard_proto::{
    client_types::{
        ClientMfaFinishRequest, ClientMfaStartRequest, MfaCodeCredential, MfaFlowApproveRequest,
        MfaFlowRemoteRequest, MfaFlowStartRequest, MfaFlowStepFinishRequest,
        MfaFlowStepStartRequest, MfaMethod, MfaMobileApprovalProof, MfaStartRejectionReason,
        mfa_flow_remote_response, mfa_flow_start_response, mfa_flow_step_finish_request,
        mfa_step_result, mfa_step_started,
    },
    proxy::{ClientMfaTokenValidationRequest, DeviceInfo},
};

use super::{
    AwaitRemoteMfaFinishRequest, ClientMfaServer, CoreResponse, MfaStartRejection, hash_token,
    remove_remote_mfa_waiter,
};
use crate::{
    events::{BidiStreamEvent, BidiStreamEventType, DesktopClientMfaEvent},
    grpc::{GatewayCommand, proxy::client_mfa::RemoteAuthWaiters},
    mfa_engine::{
        authorize::{EventChannels, create_new_session},
        multi_step::StepCredential,
    },
};

const REPLACEMENT_MFA_PRESHARED_KEY: &str = "replacement-mfa-psk";
const NEW_MFA_PRESHARED_KEY: &str = "new-psk";
const DEVICE_INFO_IP: &str = "10.0.0.7";

/// The `DeviceInfo` the proxy attaches to every bidi request; audit events are built from it.
fn device_info() -> Option<DeviceInfo> {
    Some(DeviceInfo {
        ip_address: DEVICE_INFO_IP.to_owned(),
        user_agent: Some("xguard-client/1.6.0".to_owned()),
        ..Default::default()
    })
}

#[sqlx::test]
async fn test_legacy_mfa_start_rejects_fido2(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (server, _, _) = make_server(pool);
    let error = match server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: 0,
                pubkey: String::new(),
                method: MfaMethod::Fido2 as i32,
            },
            device_info(),
        )
        .await
    {
        Ok(_) => panic!("legacy MFA start must reject FIDO2"),
        Err(MfaStartRejection::Status(error)) => error,
    };
    assert_eq!(error.code(), Code::Unimplemented);
    assert_eq!(error.message(), "Selected MFA method is not supported");
}

#[sqlx::test]
async fn test_mfa_start_rejects_non_derivable_location_with_update_message(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;

    // Assign a two-step flow so `derive_legacy_mode` returns `None`.
    let mut tx = pool.begin().await.expect("failed to begin tx");
    let (flow, _) = MfaFlow::create(
        &mut tx,
        "multi-step".to_owned(),
        vec![
            vec![VpnClientMfaMethod::Totp],
            vec![VpnClientMfaMethod::Email],
        ],
    )
    .await
    .expect("failed to create flow");
    MfaFlow::assign_to_location(
        &mut tx,
        location.id,
        &[LocationMfaFlowAssignment {
            flow_id: flow.id,
            is_default: true,
            group_ids: Vec::new(),
        }],
    )
    .await
    .expect("failed to assign flow");
    tx.commit().await.expect("failed to commit tx");

    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, _, _) = make_server(pool);

    let error = server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: location.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect_err("non-derivable location should be rejected");
    let MfaStartRejection::Status(error) = error;

    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "XGuard client version is too old to connect to this location. Please update your client."
    );
    assert!(
        !error.message().contains("no valid license"),
        "rejection message must not contain 'no valid license'"
    );
}

#[sqlx::test]
async fn test_replacing_connected_mfa_session_emits_session_superseded_event(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let location = create_mfa_location(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;
    let old_session = VpnClientSession::new(
        location.id,
        user.id,
        device.id,
        Some(Utc::now().naive_utc()),
        true,
    )
    .save(&pool)
    .await
    .expect("failed to create existing MFA session");

    let (gateway_tx, mut gateway_rx) = mpsc::unbounded_channel();
    let (bidi_event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut conn = pool.acquire().await.expect("failed to acquire connection");

    let channels = EventChannels::new(gateway_tx, bidi_event_tx);
    create_new_session(
        &channels,
        &mut conn,
        &location,
        &user,
        &device,
        true,
        REPLACEMENT_MFA_PRESHARED_KEY.to_owned().into(),
    )
    .await
    .expect("should replace connected MFA session");

    let gateway_event = gateway_rx
        .try_recv()
        .expect("expected MFA gateway disconnect event for replaced connected session");
    match gateway_event {
        GatewayCommand::VpnSessionDeauthorized(location_id, disconnected_device) => {
            assert_eq!(location_id, location.id);
            assert_eq!(disconnected_device.id, device.id);
        }
        other => panic!("unexpected gateway event: {other:?}"),
    }

    let event = event_rx
        .try_recv()
        .expect("expected session replaced audit event for replaced connected session");
    match event.event {
        BidiStreamEventType::DesktopClientMfa(event) => match *event {
            DesktopClientMfaEvent::SessionSuperseded {
                location: event_location,
                device: event_device,
                is_mfa_session,
            } => {
                assert_eq!(event_location.id, location.id);
                assert_eq!(event_device.id, device.id);
                assert!(is_mfa_session);
            }
            other => panic!("unexpected bidi event: {other:?}"),
        },
        other => panic!("unexpected bidi stream event type: {other:?}"),
    }
    assert_eq!(event.context.user_id, user.id);
    assert_eq!(event.context.username, user.username);

    let old_session = VpnClientSession::find_by_id(&pool, old_session.id)
        .await
        .expect("failed to query old session")
        .expect("expected old session");
    assert_eq!(old_session.state, VpnClientSessionState::Disconnected);
}

#[sqlx::test]
async fn test_replacing_new_mfa_session_marks_session_disconnected_without_disconnect_audit_event(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let location = create_mfa_location(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;
    let old_session = VpnClientSession::new(location.id, user.id, device.id, None, true)
        .save(&pool)
        .await
        .expect("failed to create existing new MFA session");

    let (gateway_tx, mut gateway_rx) = mpsc::unbounded_channel();
    let (bidi_event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut conn = pool.acquire().await.expect("failed to acquire connection");

    let channels = EventChannels::new(gateway_tx, bidi_event_tx);
    create_new_session(
        &channels,
        &mut conn,
        &location,
        &user,
        &device,
        true,
        REPLACEMENT_MFA_PRESHARED_KEY.to_owned().into(),
    )
    .await
    .expect("should replace new MFA session");

    let gateway_event = gateway_rx
        .try_recv()
        .expect("expected MFA gateway disconnect event for replaced new session");
    match gateway_event {
        GatewayCommand::VpnSessionDeauthorized(location_id, disconnected_device) => {
            assert_eq!(location_id, location.id);
            assert_eq!(disconnected_device.id, device.id);
        }
        other => panic!("unexpected gateway event: {other:?}"),
    }

    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let old_session = VpnClientSession::find_by_id(&pool, old_session.id)
        .await
        .expect("failed to query old session")
        .expect("expected old session");
    assert_eq!(old_session.state, VpnClientSessionState::Disconnected);
}

fn make_server(
    pool: PgPool,
) -> (
    ClientMfaServer,
    mpsc::UnboundedReceiver<BidiStreamEvent>,
    mpsc::UnboundedReceiver<GatewayCommand>,
) {
    let (gateway_tx, gateway_rx) = mpsc::unbounded_channel();
    let (bidi_event_tx, bidi_event_rx) = mpsc::unbounded_channel();
    let remote_mfa_responses: RemoteAuthWaiters = Arc::default();

    (
        ClientMfaServer::new(pool, gateway_tx, bidi_event_tx, remote_mfa_responses),
        bidi_event_rx,
        gateway_rx,
    )
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn next_suffix() -> usize {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

async fn create_user(pool: &PgPool) -> User<Id> {
    let suffix = next_suffix();
    User::new(
        format!("client-mfa-test-{suffix}"),
        Some("pass123"),
        "Tester".to_owned(),
        "ClientMfa".to_owned(),
        format!("client-mfa-{suffix}@example.com"),
        None,
    )
    .save(pool)
    .await
    .expect("failed to create user")
}

async fn create_device(pool: &PgPool, user_id: Id) -> Device<Id> {
    let suffix = next_suffix();
    Device::new(
        format!("client-mfa-device-{suffix}"),
        format!("client-mfa-pubkey-{suffix}"),
        user_id,
        DeviceType::User,
        None,
        true,
    )
    .save(pool)
    .await
    .expect("failed to create device")
}

#[sqlx::test]
async fn test_create_new_mfa_session_disconnects_previous_active_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let location = create_mfa_location(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let mut previous_session = VpnClientSession::new(
        location.id,
        user.id,
        device.id,
        Some(Utc::now().naive_utc()),
        true,
    );
    previous_session.preshared_key = Some("old-psk".to_owned().into());
    previous_session.state = VpnClientSessionState::Connected;
    let previous_session = previous_session
        .save(&pool)
        .await
        .expect("failed to create previous active MFA session");

    let (gateway_tx, mut gateway_rx) = mpsc::unbounded_channel();
    let (bidi_event_tx, _bidi_event_rx) = mpsc::unbounded_channel();
    let mut conn = pool
        .acquire()
        .await
        .expect("failed to acquire database connection");

    let channels = EventChannels::new(gateway_tx, bidi_event_tx);
    let new_session = create_new_session(
        &channels,
        &mut conn,
        &location,
        &user,
        &device,
        true,
        NEW_MFA_PRESHARED_KEY.to_owned().into(),
    )
    .await
    .expect("failed to create replacement MFA session");

    let previous_session = VpnClientSession::find_by_id(&pool, previous_session.id)
        .await
        .expect("failed to reload previous session")
        .expect("expected previous session to exist");
    assert_eq!(previous_session.state, VpnClientSessionState::Disconnected);
    assert!(previous_session.disconnected_at.is_some());

    let active_sessions =
        VpnClientSession::get_all_active_device_sessions_in_location(&pool, location.id, device.id)
            .await
            .expect("failed to fetch active sessions");
    assert_eq!(active_sessions.len(), 1);
    assert_eq!(active_sessions[0].id, new_session.id);
    assert_eq!(
        active_sessions[0]
            .preshared_key
            .as_ref()
            .map(SecretStringWrapper::expose_secret),
        Some(NEW_MFA_PRESHARED_KEY)
    );

    match gateway_rx.try_recv() {
        Ok(GatewayCommand::VpnSessionDeauthorized(location_id, disconnected_device)) => {
            assert_eq!(location_id, location.id);
            assert_eq!(disconnected_device.id, device.id);
        }
        Ok(other) => panic!("unexpected gateway event: {other:?}"),
        Err(error) => panic!("expected MFA disconnect gateway event, got {error:?}"),
    }
}

async fn create_mfa_location(pool: &PgPool) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        "client-mfa-location".to_owned(),
        51820,
        "vpn.example.com".to_owned(),
        None,
        [IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
        true,
        false,
        false,
        false,
        true, // mfa_enabled
        ServiceLocationMode::Disabled,
    )
    .set_address([IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1)), 24).unwrap()])
    .expect("failed to set location address")
    .save(pool)
    .await
    .expect("failed to create location")
}

async fn attach_device_to_location(pool: &PgPool, location_id: Id, device_id: Id) {
    WireguardNetworkDevice::new(
        location_id,
        device_id,
        vec![IpAddr::V4(Ipv4Addr::new(10, 10, 0, 10))],
    )
    .insert(pool)
    .await
    .expect("failed to attach device to location");
}

async fn create_and_assign_mfa_flow(pool: &PgPool, location_id: Id) {
    let mut tx = pool.begin().await.expect("failed to begin transaction");
    let (flow, _steps) = MfaFlow::create(
        &mut tx,
        "Default Internal MFA".into(),
        vec![vec![
            VpnClientMfaMethod::Totp,
            VpnClientMfaMethod::Email,
            VpnClientMfaMethod::Biometric,
            VpnClientMfaMethod::MobileApprove,
        ]],
    )
    .await
    .expect("failed to create MFA flow");
    MfaFlow::assign_to_location(
        &mut tx,
        location_id,
        &[LocationMfaFlowAssignment {
            flow_id: flow.id,
            is_default: true,
            group_ids: Vec::new(),
        }],
    )
    .await
    .expect("failed to assign MFA flow to location");
    tx.commit().await.expect("failed to commit transaction");
}

async fn setup_mfa_flow_server(options: PgConnectOptions) -> (ClientMfaServer, PgPool, Id, String) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    user.enable_totp(&pool)
        .await
        .expect("failed to enable TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;
    BiometricAuth::new(device.id, "mobile-approve-test-key".to_owned())
        .save(&pool)
        .await
        .expect("failed to register mobile authenticator");
    let pubkey = device.wireguard_pubkey.clone();
    let (server, _event_rx, _gateway_rx) = make_server(pool.clone());
    (server, pool, location.id, pubkey)
}

async fn setup_mobile_mfa_flow_server(
    options: PgConnectOptions,
) -> (
    ClientMfaServer,
    PgPool,
    Id,
    String,
    String,
    SigningKey,
    mpsc::UnboundedReceiver<BidiStreamEvent>,
    mpsc::UnboundedReceiver<GatewayCommand>,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;
    let signing_key = SigningKey::from_bytes(&[11; 32]);
    let auth_pub_key = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
    BiometricAuth::new(device.id, auth_pub_key.clone())
        .save(&pool)
        .await
        .expect("failed to register mobile authenticator");
    let pubkey = device.wireguard_pubkey.clone();
    let (server, event_rx, gateway_rx) = make_server(pool.clone());
    (
        server,
        pool,
        location.id,
        pubkey,
        auth_pub_key,
        signing_key,
        event_rx,
        gateway_rx,
    )
}

async fn setup_totp_mfa_server(
    options: PgConnectOptions,
) -> (
    ClientMfaServer,
    Id,
    String,
    String,
    mpsc::UnboundedReceiver<BidiStreamEvent>,
    mpsc::UnboundedReceiver<GatewayCommand>,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    user.enable_totp(&pool)
        .await
        .expect("failed to enable TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, event_rx, gateway_rx) = make_server(pool);
    let start = server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: location.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect("start should succeed");
    let token = start.token;

    (
        server,
        location.id,
        device.wireguard_pubkey,
        token,
        event_rx,
        gateway_rx,
    )
}

fn assert_core_error_response(
    response: Option<CoreResponse>,
    request_id: u64,
    status: Code,
    message: &str,
) {
    let response = response.expect("parked waiter should receive a response");
    assert_eq!(response.id, request_id);
    let Some(super::Payload::CoreError(error)) = response.payload else {
        panic!("expected a CoreError response");
    };
    assert_eq!(error.status_code, status as i32);
    assert_eq!(error.message, message);
}

fn assert_superseded_response(response: Option<CoreResponse>, request_id: u64) {
    assert_core_error_response(
        response,
        request_id,
        Code::Aborted,
        "remote MFA wait superseded",
    );
}

#[test]
fn test_remote_waiters_are_scoped_by_contract_and_attempt() {
    let waiters: RemoteAuthWaiters = Arc::default();
    let (multi_signal_tx, _multi_signal_rx) = oneshot::channel();
    waiters.write().unwrap().insert(
        hash_token("multi-token"),
        super::RemoteAuthWaiter {
            waiter_identity: Arc::new(()),
            signal_tx: multi_signal_tx,
            kind: super::RemoteAuthWaiterKind::MultiStep {
                step_attempt_id: "current-attempt".to_owned(),
            },
        },
    );

    assert!(super::take_legacy_remote_mfa_waiter(&waiters, "multi-token").is_none());
    assert!(
        super::take_multi_step_remote_mfa_waiter(&waiters, "multi-token", "stale-attempt")
            .is_none()
    );
    assert!(
        super::take_multi_step_remote_mfa_waiter(&waiters, "multi-token", "current-attempt")
            .is_some()
    );

    let (legacy_signal_tx, _legacy_signal_rx) = oneshot::channel();
    waiters.write().unwrap().insert(
        hash_token("legacy-token"),
        super::RemoteAuthWaiter {
            waiter_identity: Arc::new(()),
            signal_tx: legacy_signal_tx,
            kind: super::RemoteAuthWaiterKind::Legacy {
                preshared_key: Arc::new(std::sync::Mutex::new(None)),
            },
        },
    );
    assert!(
        super::take_multi_step_remote_mfa_waiter(&waiters, "legacy-token", "current-attempt")
            .is_none()
    );
    assert!(super::take_legacy_remote_mfa_waiter(&waiters, "legacy-token").is_some());
}

#[test]
fn test_remove_remote_mfa_waiter_only_removes_matching_identity() {
    let waiters: RemoteAuthWaiters = Arc::default();
    let stale_waiter_identity = Arc::new(());
    let current_waiter_identity = Arc::new(());
    let (signal_tx, _signal_rx) = oneshot::channel();

    waiters.write().unwrap().insert(
        "test-hash".to_owned(),
        super::RemoteAuthWaiter {
            waiter_identity: current_waiter_identity.clone(),
            signal_tx,
            kind: super::RemoteAuthWaiterKind::Legacy {
                preshared_key: Arc::new(std::sync::Mutex::new(None)),
            },
        },
    );

    remove_remote_mfa_waiter(&waiters, "test-hash", &stale_waiter_identity);
    assert!(waiters.read().unwrap().contains_key("test-hash"));

    remove_remote_mfa_waiter(&waiters, "test-hash", &current_waiter_identity);
    assert!(!waiters.read().unwrap().contains_key("test-hash"));
}

#[sqlx::test]
async fn test_duplicate_remote_mfa_park_supersedes_old_waiter_and_preserves_newer(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, _location_id, _pubkey, token, _event_rx, _gateway_rx) =
        setup_totp_mfa_server(options).await;
    let hash = hash_token(&token);

    let (first_response_tx, mut first_response_rx) = mpsc::unbounded_channel();
    server
        .legacy_mfa_remote(
            AwaitRemoteMfaFinishRequest {
                token: token.clone(),
            },
            first_response_tx,
            1,
            device_info(),
        )
        .await
        .expect("first waiter should park");

    let (second_response_tx, mut second_response_rx) = mpsc::unbounded_channel();
    server
        .legacy_mfa_remote(
            AwaitRemoteMfaFinishRequest {
                token: token.clone(),
            },
            second_response_tx,
            2,
            device_info(),
        )
        .await
        .expect("second waiter should replace the first");

    let first_response = timeout(Duration::from_secs(1), first_response_rx.recv())
        .await
        .expect("old waiter should finish after replacement");
    let newer_waiter_registered = server
        .remote_mfa_responses
        .read()
        .expect("failed to read remote MFA waiters")
        .contains_key(&hash);

    server
        .remote_mfa_responses
        .write()
        .expect("failed to write remote MFA waiters")
        .remove(&hash);
    let second_response = timeout(Duration::from_secs(1), second_response_rx.recv())
        .await
        .expect("newer waiter cleanup should finish");

    assert_core_error_response(
        second_response,
        2,
        Code::Internal,
        "remote MFA signal channel closed",
    );
    assert!(
        newer_waiter_registered,
        "old waiter cleanup must not remove the newer waiter"
    );
    assert_superseded_response(first_response, 1);
}

#[sqlx::test]
async fn test_legacy_mfa_remote_timeout_sends_terminal_error(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, _location_id, _pubkey, token, _event_rx, _gateway_rx) =
        setup_totp_mfa_server(options).await;
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .legacy_mfa_remote_with_timeout(
            AwaitRemoteMfaFinishRequest {
                token: token.clone(),
            },
            response_tx,
            3,
            Duration::from_millis(1),
        )
        .await
        .expect("remote waiter should park");

    let response = timeout(Duration::from_secs(1), response_rx.recv())
        .await
        .expect("timed-out legacy waiter should finish");
    assert_core_error_response(
        response,
        3,
        Code::DeadlineExceeded,
        "remote MFA wait timed out",
    );
    assert!(
        !server
            .remote_mfa_responses
            .read()
            .expect("failed to read remote MFA waiters")
            .contains_key(&hash_token(&token)),
        "timeout should remove the waiter"
    );
}

#[sqlx::test]
async fn test_legacy_mfa_start_supersedes_parked_waiter_with_defined_result(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, location_id, pubkey, token, _event_rx, _gateway_rx) =
        setup_totp_mfa_server(options).await;
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .legacy_mfa_remote(
            AwaitRemoteMfaFinishRequest {
                token: token.clone(),
            },
            response_tx,
            1,
            device_info(),
        )
        .await
        .expect("waiter should park");
    assert!(
        server
            .remote_mfa_responses
            .read()
            .expect("failed to read remote MFA waiters")
            .contains_key(&hash_token(&token)),
        "waiter should be registered before the replacement start"
    );

    let replacement = server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id,
                pubkey,
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect("replacement start should succeed");
    assert_ne!(replacement.token, "");

    let response = timeout(Duration::from_secs(1), response_rx.recv())
        .await
        .expect("superseded waiter should finish after replacement start");
    assert_superseded_response(response, 1);
}

#[sqlx::test]
async fn test_legacy_mfa_finish_totp_authorizes_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    let secret = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    user.totp_secret = Some(secret.clone());
    user.totp_enabled = true;
    user.save(&pool).await.expect("failed to configure TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, mut event_rx, _gateway_rx) = make_server(pool.clone());

    let start = server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: location.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect("start should succeed");
    let token = start.token;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp_custom::<Sha1>(
        TOTP_CODE_VALIDITY_PERIOD,
        TOTP_CODE_DIGITS,
        &secret,
        timestamp,
    );

    let response = server
        .legacy_mfa_finish(
            ClientMfaFinishRequest {
                token: token.clone(),
                code: Some(code),
                auth_pub_key: None,
            },
            device_info(),
        )
        .await
        .expect("finish should succeed");
    assert_ne!(response.preshared_key, "");

    // The successful finish is audited.
    let event = event_rx
        .try_recv()
        .expect("expected desktop client MFA success event");
    match event.event {
        BidiStreamEventType::DesktopClientMfa(event) => match *event {
            DesktopClientMfaEvent::Success {
                attribution:
                    MfaAttribution {
                        snapshot,
                        flow_name,
                    },
                ..
            } => {
                assert_eq!(flow_name.as_deref(), Some("Default Internal MFA"));
                assert_eq!(snapshot.steps.len(), 1);
                assert_eq!(snapshot.steps[0].satisfied, Some(VpnClientMfaMethod::Totp));
                assert!(
                    snapshot.steps[0]
                        .methods
                        .contains(&VpnClientMfaMethod::Totp)
                );
            }
            other => panic!("unexpected bidi event: {other:?}"),
        },
        other => panic!("unexpected bidi stream event type: {other:?}"),
    }

    // The authorized session records only that MFA was used.
    let sessions =
        VpnClientSession::get_all_active_device_sessions_in_location(&pool, location.id, device.id)
            .await
            .expect("failed to fetch active sessions");
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].is_mfa_session);

    // The in-progress session is gone.
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn test_legacy_mfa_finish_failure_cap_deletes_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    let secret = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    user.totp_secret = Some(secret);
    user.totp_enabled = true;
    user.save(&pool).await.expect("failed to configure TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, mut event_rx, _gateway_rx) = make_server(pool.clone());

    let start = server
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: location.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect("start should succeed");
    let token = start.token;

    // Repeating a wrong code trips the per-step cap and deletes the session.
    for _ in 0..MFA_FAILED_ATTEMPT_CAP {
        let result = server
            .legacy_mfa_finish(
                ClientMfaFinishRequest {
                    token: token.clone(),
                    code: Some("000000".to_owned()),
                    auth_pub_key: None,
                },
                device_info(),
            )
            .await;
        assert!(result.is_err());
    }

    // The session is deleted once the cap is reached.
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .unwrap()
            .is_none()
    );

    // Each rejected proof is audited.
    for _ in 0..MFA_FAILED_ATTEMPT_CAP {
        let event = event_rx
            .try_recv()
            .expect("expected desktop client MFA failed event");
        match event.event {
            BidiStreamEventType::DesktopClientMfa(event) => match *event {
                DesktopClientMfaEvent::Failed { .. } => {}
                other => panic!("unexpected bidi event: {other:?}"),
            },
            other => panic!("unexpected bidi stream event type: {other:?}"),
        }
    }
}

async fn start_mfa_session_direct(pool: &PgPool, ttl: Duration) -> String {
    let location = create_mfa_location(pool).await;
    let user = create_user(pool).await;
    let device = create_device(pool, user.id).await;
    let mut tx = pool.begin().await.unwrap();
    let (_, outcome) = VpnClientMfaSession::<Id>::start(
        &mut tx,
        location.id,
        device.id,
        user.id,
        1,
        vec![vec![VpnClientMfaMethod::Totp]],
        VpnMfaFlowKind::Legacy,
        VpnClientMfaMethod::Totp,
        None,
        ttl,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome.token
}

#[sqlx::test]
async fn test_validate_mfa_token(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (server, _event_rx, _gateway_rx) = make_server(pool.clone());

    // Unknown token.
    let resp = server
        .validate_mfa_token(ClientMfaTokenValidationRequest {
            token: "nonexistent".to_owned(),
        })
        .await
        .unwrap();
    assert!(!resp.token_valid);

    // Expired token.
    let expired = start_mfa_session_direct(&pool, Duration::ZERO).await;
    let resp = server
        .validate_mfa_token(ClientMfaTokenValidationRequest { token: expired })
        .await
        .unwrap();
    assert!(!resp.token_valid);

    // Active token.
    let active = start_mfa_session_direct(&pool, VPN_MFA_SESSION_TIMEOUT).await;
    let resp = server
        .validate_mfa_token(ClientMfaTokenValidationRequest { token: active })
        .await
        .unwrap();
    assert!(resp.token_valid);
}

#[sqlx::test]
async fn test_mfa_flow_remote_wakes_matching_attempt_and_delivers_psk(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, pool, location_id, pubkey, auth_pub_key, signing_key, _event_rx, _gateway_rx) =
        setup_mobile_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey: pubkey.clone(),
                selected_methods: vec![MfaMethod::MobileApprove as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should be accepted");
    };
    let first_step = accepted
        .first_step
        .expect("flow start must include an attempt");
    let challenge = match first_step
        .challenge
        .expect("MobileApprove must include a signature challenge")
    {
        mfa_step_started::Challenge::Signature(challenge) => challenge.challenge,
        other @ mfa_step_started::Challenge::Fido2(_) => panic!("unexpected challenge: {other:?}"),
    };
    let token = accepted.token;
    let step_attempt_id = first_step.step_attempt_id;
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .mfa_flow_remote(
            MfaFlowRemoteRequest {
                token: token.clone(),
                step_attempt_id: step_attempt_id.clone(),
            },
            response_tx,
            42,
            device_info(),
        )
        .await
        .expect("remote waiter should park");
    assert!(
        server
            .remote_mfa_responses
            .read()
            .expect("failed to read remote MFA waiters")
            .contains_key(&hash_token(&token))
    );

    let stale_error = server
        .mfa_flow_approve(
            MfaFlowApproveRequest {
                token: token.clone(),
                step_attempt_id: "stale-attempt".to_owned(),
                proof: Some(MfaMobileApprovalProof {
                    signature: String::new(),
                    auth_pub_key: auth_pub_key.clone(),
                }),
            },
            device_info(),
        )
        .await
        .expect_err("a mismatched approval must be rejected");
    assert_eq!(stale_error.code(), Code::InvalidArgument);
    assert_eq!(stale_error.message(), "stale MFA attempt");
    assert!(response_rx.try_recv().is_err());
    assert!(
        server
            .remote_mfa_responses
            .read()
            .expect("failed to read remote MFA waiters")
            .contains_key(&hash_token(&token))
    );

    let signature = BASE64_STANDARD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());
    server
        .mfa_flow_approve(
            MfaFlowApproveRequest {
                token: token.clone(),
                step_attempt_id,
                proof: Some(MfaMobileApprovalProof {
                    signature,
                    auth_pub_key,
                }),
            },
            device_info(),
        )
        .await
        .expect("matching approval should wake the remote waiter");

    let response = timeout(Duration::from_secs(2), response_rx.recv())
        .await
        .expect("remote waiter should finish after approval")
        .expect("remote response sender should remain available");
    let Some(super::Payload::MfaFlowRemote(response)) = response.payload else {
        panic!("expected a typed remote flow response");
    };
    let Some(mfa_flow_remote_response::Outcome::Result(result)) = response.outcome else {
        panic!("remote response must include a result");
    };
    let Some(mfa_step_result::Outcome::Completed(completed)) = result.outcome else {
        panic!("expected a completed remote result");
    };
    assert_ne!(completed.preshared_key, "");
    let remote_preshared_key = completed.preshared_key;
    assert!(
        server
            .remote_mfa_responses
            .read()
            .expect("failed to read remote MFA waiters")
            .is_empty()
    );
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .expect("session lookup should succeed")
            .is_none()
    );
    let device = Device::find_by_pubkey(&pool, &pubkey)
        .await
        .expect("device lookup should succeed")
        .expect("device should exist");
    let sessions =
        VpnClientSession::get_all_active_device_sessions_in_location(&pool, location_id, device.id)
            .await
            .expect("VPN session lookup should succeed");
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        Some(remote_preshared_key.as_str()),
        sessions[0]
            .preshared_key
            .as_ref()
            .map(SecretStringWrapper::expose_secret)
    );
}

#[sqlx::test]
async fn test_mfa_flow_remote_observes_approval_before_registration(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, pool, location_id, pubkey, auth_pub_key, signing_key, _event_rx, _gateway_rx) =
        setup_mobile_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey: pubkey.clone(),
                selected_methods: vec![MfaMethod::MobileApprove as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should be accepted");
    };
    let first_step = accepted
        .first_step
        .expect("flow start must include an attempt");
    let challenge = match first_step
        .challenge
        .expect("MobileApprove must include a signature challenge")
    {
        mfa_step_started::Challenge::Signature(challenge) => challenge.challenge,
        other @ mfa_step_started::Challenge::Fido2(_) => panic!("unexpected challenge: {other:?}"),
    };
    let token = accepted.token;
    let step_attempt_id = first_step.step_attempt_id;
    let signature = BASE64_STANDARD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

    server
        .mfa_flow_approve(
            MfaFlowApproveRequest {
                token: token.clone(),
                step_attempt_id: step_attempt_id.clone(),
                proof: Some(MfaMobileApprovalProof {
                    signature,
                    auth_pub_key,
                }),
            },
            device_info(),
        )
        .await
        .expect("approval should be marked before remote waiting starts");
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .expect("session lookup should succeed")
            .is_some()
    );
    let device = Device::find_by_pubkey(&pool, &pubkey)
        .await
        .expect("device lookup should succeed")
        .expect("device should exist");
    assert!(
        VpnClientSession::get_all_active_device_sessions_in_location(
            &pool,
            location_id,
            device.id,
        )
        .await
        .expect("VPN session lookup should succeed")
        .is_empty()
    );

    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .mfa_flow_remote(
            MfaFlowRemoteRequest {
                token: token.clone(),
                step_attempt_id,
            },
            response_tx,
            43,
            device_info(),
        )
        .await
        .expect("remote waiter should observe the durable approval");
    let response = timeout(Duration::from_secs(2), response_rx.recv())
        .await
        .expect("remote waiter should finish")
        .expect("remote response sender should remain available");
    let Some(super::Payload::MfaFlowRemote(response)) = response.payload else {
        panic!("expected a typed remote flow response");
    };
    let Some(mfa_flow_remote_response::Outcome::Result(result)) = response.outcome else {
        panic!("remote response must include a result");
    };
    let Some(mfa_step_result::Outcome::Completed(completed)) = result.outcome else {
        panic!("expected a completed remote result");
    };
    assert_ne!(completed.preshared_key, "");
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .expect("session lookup should succeed")
            .is_none()
    );
}

#[sqlx::test]
async fn test_mfa_flow_remote_timeout_cleans_its_waiter(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, pool, location_id, pubkey, _auth_pub_key, _signing_key, _event_rx, _gateway_rx) =
        setup_mobile_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey: pubkey.clone(),
                selected_methods: vec![MfaMethod::MobileApprove as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should be accepted");
    };
    let step_attempt_id = accepted
        .first_step
        .expect("flow start must include an attempt")
        .step_attempt_id;
    let token = accepted.token;
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .mfa_flow_remote_with_timeout(
            MfaFlowRemoteRequest {
                token: token.clone(),
                step_attempt_id: step_attempt_id.clone(),
            },
            response_tx,
            44,
            device_info(),
            Duration::from_millis(1),
        )
        .await
        .expect("remote waiter should park");

    timeout(Duration::from_secs(1), async {
        loop {
            if server
                .remote_mfa_responses
                .read()
                .expect("failed to read remote MFA waiters")
                .is_empty()
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("timeout cleanup should remove the owning waiter");
    let response = timeout(Duration::from_secs(1), response_rx.recv())
        .await
        .expect("timed-out remote waiter should send a response");
    assert_core_error_response(
        response,
        44,
        Code::DeadlineExceeded,
        "remote MFA wait timed out",
    );

    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    server
        .mfa_flow_remote_with_timeout(
            MfaFlowRemoteRequest {
                token: token.clone(),
                step_attempt_id,
            },
            response_tx,
            45,
            device_info(),
            Duration::from_secs(5),
        )
        .await
        .expect("remote waiter should park");
    let waiter = server
        .remote_mfa_responses
        .write()
        .expect("failed to write remote MFA waiters")
        .remove(&hash_token(&token))
        .expect("parked waiter should be registered");
    drop(waiter);
    let response = timeout(Duration::from_secs(1), response_rx.recv())
        .await
        .expect("closed signal receiver should send a response");
    assert_core_error_response(
        response,
        45,
        Code::Internal,
        "remote MFA signal channel closed",
    );
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &token)
            .await
            .expect("session lookup should succeed")
            .is_some()
    );
    let device = Device::find_by_pubkey(&pool, &pubkey)
        .await
        .expect("device lookup should succeed")
        .expect("device should exist");
    assert!(
        VpnClientSession::get_all_active_device_sessions_in_location(
            &pool,
            location_id,
            device.id,
        )
        .await
        .expect("VPN session lookup should succeed")
        .is_empty()
    );
}

#[sqlx::test]
async fn test_mfa_flow_start_returns_initial_attempt(_: PgPoolOptions, options: PgConnectOptions) {
    let (server, pool, location_id, pubkey) = setup_mfa_flow_server(options).await;
    let outcome = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey,
                selected_methods: vec![MfaMethod::Totp as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = outcome;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should return an accepted outcome");
    };
    let first_step = accepted
        .first_step
        .expect("accepted flow start must include the first step");
    assert_ne!(accepted.token, "");
    assert_ne!(first_step.step_attempt_id, "");
    assert!(first_step.challenge.is_none());

    let session = VpnClientMfaSession::<Id>::find_active_by_token(&pool, &accepted.token)
        .await
        .expect("session lookup should succeed")
        .expect("flow start must persist a session");
    assert_eq!(session.flow_kind, VpnMfaFlowKind::MultiStep);
    assert_eq!(
        first_step.step_attempt_id,
        session
            .ephemeral_state
            .as_ref()
            .expect("flow start must persist an attempt")
            .0
            .step_attempt_id
    );
}

#[sqlx::test]
async fn test_mfa_flow_start_rejection_does_not_create_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, pool, location_id, pubkey) = setup_mfa_flow_server(options).await;
    let outcome = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey,
                selected_methods: vec![MfaMethod::Fido2 as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should return a typed rejection");
    let response = outcome;
    let Some(mfa_flow_start_response::Outcome::Rejected(rejected)) = response.outcome else {
        panic!("flow start should return a rejected outcome");
    };
    assert_eq!(rejected.rejections.len(), 1);
    assert_eq!(rejected.rejections[0].step, 0);
    assert_eq!(
        rejected.rejections[0].reason,
        MfaStartRejectionReason::MfaStartRejectionMethodNotInStep as i32
    );
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM vpn_client_mfa_session WHERE location_id = $1")
            .bind(location_id)
            .fetch_one(&pool)
            .await
            .expect("session count should succeed");
    assert_eq!(session_count, 0);
}

#[sqlx::test]
async fn test_mfa_flow_step_start_returns_typed_attempt(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, pool, location_id, pubkey) = setup_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey,
                selected_methods: vec![MfaMethod::Totp as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should return an accepted outcome");
    };
    let initial_attempt = accepted
        .first_step
        .expect("accepted flow start must include the first step")
        .step_attempt_id;

    let step = server
        .mfa_flow_step_start(MfaFlowStepStartRequest {
            token: accepted.token.clone(),
            method: MfaMethod::MobileApprove as i32,
        })
        .await
        .expect("flow step start should succeed");
    let started = step.started.expect("step start must include its result");
    assert_ne!(started.step_attempt_id, "");
    assert_ne!(started.step_attempt_id, initial_attempt);
    let Some(mfa_step_started::Challenge::Signature(challenge)) = started.challenge else {
        panic!("mobile-approve step start should return a signature challenge");
    };
    assert_ne!(challenge.challenge, "");

    let session = VpnClientMfaSession::<Id>::find_active_by_token(&pool, &accepted.token)
        .await
        .expect("session lookup should succeed")
        .expect("flow step start must preserve the session");
    assert_eq!(
        started.step_attempt_id,
        session
            .ephemeral_state
            .as_ref()
            .expect("flow step start must persist an attempt")
            .0
            .step_attempt_id
    );
}

#[test]
fn test_encode_step_started_uses_typed_challenge_arms() {
    let signature = super::encode_step_started(
        VpnClientMfaMethod::MobileApprove,
        "signature-attempt".to_owned(),
        Some("signature-challenge".to_owned()),
        Vec::new(),
    )
    .expect("signature challenge should be well formed");
    assert!(matches!(
        signature.challenge,
        Some(mfa_step_started::Challenge::Signature(challenge))
            if challenge.challenge == "signature-challenge"
    ));

    let fido2 = super::encode_step_started(
        VpnClientMfaMethod::Fido2,
        "fido2-attempt".to_owned(),
        Some("fido2-challenge".to_owned()),
        vec!["credential".to_owned()],
    )
    .expect("FIDO2 challenge should be well formed");
    assert!(matches!(
        fido2.challenge,
        Some(mfa_step_started::Challenge::Fido2(challenge))
            if challenge.challenge == "fido2-challenge"
                && challenge.credential_ids == ["credential"]
    ));
}

#[sqlx::test]
async fn test_mfa_flow_step_finish_rejects_untyped_totp_submission(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let (server, _pool, location_id, pubkey) = setup_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey,
                selected_methods: vec![MfaMethod::Totp as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should be accepted");
    };
    let attempt_id = accepted
        .first_step
        .expect("flow start must include an attempt")
        .step_attempt_id;
    let error = server
        .mfa_flow_step_finish(
            MfaFlowStepFinishRequest {
                token: accepted.token,
                step_attempt_id: attempt_id,
                submission: None,
            },
            device_info(),
        )
        .await;
    let Err(error) = error else {
        panic!("a TOTP step must reject an empty typed submission");
    };
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "MFA credential does not match the selected method"
    );
}

#[test]
fn test_flow_step_finish_converts_typed_code_submission() {
    let (token, proof) = super::into_step_proof(MfaFlowStepFinishRequest {
        token: "token".to_owned(),
        step_attempt_id: "attempt".to_owned(),
        submission: Some(mfa_flow_step_finish_request::Submission::Code(
            MfaCodeCredential {
                code: "123456".to_owned(),
            },
        )),
    });
    assert_eq!(token, "token");
    assert_eq!(proof.step_attempt_id, "attempt");
    assert_eq!(
        proof.credential,
        Some(StepCredential::Code("123456".to_owned()))
    );
}

#[sqlx::test]
async fn test_mfa_flow_remote_rejects_non_mobile_step(_: PgPoolOptions, options: PgConnectOptions) {
    let (server, _pool, location_id, pubkey) = setup_mfa_flow_server(options).await;
    let start = server
        .mfa_flow_start(
            MfaFlowStartRequest {
                posture: None,
                location_id,
                pubkey,
                selected_methods: vec![MfaMethod::Totp as i32],
            },
            device_info(),
        )
        .await
        .expect("flow start should succeed");
    let response = start;
    let Some(mfa_flow_start_response::Outcome::Accepted(accepted)) = response.outcome else {
        panic!("flow start should be accepted");
    };
    let attempt_id = accepted
        .first_step
        .expect("flow start must include an attempt")
        .step_attempt_id;
    let (response_tx, _response_rx) = mpsc::unbounded_channel();
    let error = server
        .mfa_flow_remote(
            MfaFlowRemoteRequest {
                token: accepted.token,
                step_attempt_id: attempt_id,
            },
            response_tx,
            1,
            device_info(),
        )
        .await
        .expect_err("remote waiting must reject a non-MobileApprove step");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.message(), "MFA method is not MobileApprove");
}

#[sqlx::test]
async fn test_legacy_mfa_start_supersedes_existing_session(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    user.enable_totp(&pool)
        .await
        .expect("failed to enable TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, mut event_rx, _gateway_rx) = make_server(pool.clone());

    let request = || ClientMfaStartRequest {
        posture: None,
        location_id: location.id,
        pubkey: device.wireguard_pubkey.clone(),
        method: MfaMethod::Totp as i32,
    };

    let first = server
        .legacy_mfa_start(request(), device_info())
        .await
        .expect("first start should succeed");
    let first_token = first.token;
    let first_session = VpnClientMfaSession::<Id>::find_active_by_token(&pool, &first_token)
        .await
        .unwrap()
        .expect("legacy start must persist a session");
    assert_eq!(first_session.flow_kind, VpnMfaFlowKind::Legacy);

    let second = server
        .legacy_mfa_start(request(), device_info())
        .await
        .expect("second start should succeed");
    let second_token = second.token;

    // The first token no longer validates; the second one does.
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &first_token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &second_token)
            .await
            .unwrap()
            .is_some()
    );

    let event = event_rx
        .try_recv()
        .expect("expected an audit event for the superseded login");
    match event.event {
        BidiStreamEventType::DesktopClientMfa(event) => match *event {
            DesktopClientMfaEvent::MfaLoginSuperseded {
                location: event_location,
                device: event_device,
            } => {
                assert_eq!(event_location.id, location.id);
                assert_eq!(event_device.id, device.id);
            }
            other => panic!("unexpected bidi event: {other:?}"),
        },
        other => panic!("unexpected bidi stream event type: {other:?}"),
    }
}

/// Malformed device info is rejected before anything is written. Were it parsed after the
/// session was persisted, the failing request would leave a live orphan row behind and,
/// worse, would already have superseded the caller's previous session.
#[sqlx::test]
async fn test_legacy_mfa_start_rejects_bad_device_info_without_persisting(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    user.enable_totp(&pool)
        .await
        .expect("failed to enable TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    let (server, _event_rx, _gateway_rx) = make_server(pool.clone());

    let request = || ClientMfaStartRequest {
        posture: None,
        location_id: location.id,
        pubkey: device.wireguard_pubkey.clone(),
        method: MfaMethod::Totp as i32,
    };

    let established = server
        .legacy_mfa_start(request(), device_info())
        .await
        .expect("first start should succeed");
    let established_token = established.token;

    // A start carrying no device info must fail.
    assert!(
        server.legacy_mfa_start(request(), None).await.is_err(),
        "start without device info should be rejected"
    );

    // The established session is untouched, and no orphan row was left behind.
    assert!(
        VpnClientMfaSession::<Id>::find_active_by_token(&pool, &established_token)
            .await
            .unwrap()
            .is_some()
    );
    let rows = sqlx::query_scalar!(
        "SELECT count(*) FROM vpn_client_mfa_session WHERE location_id = $1 AND device_id = $2",
        location.id,
        device.id,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, Some(1));
}

#[sqlx::test]
async fn test_finish_survives_server_restart(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    let location = create_mfa_location(&pool).await;
    create_and_assign_mfa_flow(&pool, location.id).await;
    let mut user = create_user(&pool).await;
    let secret = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    user.totp_secret = Some(secret.clone());
    user.totp_enabled = true;
    user.save(&pool).await.expect("failed to configure TOTP");
    let device = create_device(&pool, user.id).await;
    attach_device_to_location(&pool, location.id, device.id).await;

    // Start the login on one server instance.
    let (server_a, _event_rx, _gateway_rx) = make_server(pool.clone());
    let start = server_a
        .legacy_mfa_start(
            ClientMfaStartRequest {
                posture: None,
                location_id: location.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
            },
            device_info(),
        )
        .await
        .expect("start should succeed");
    let token = start.token;

    // A "restart" is a fresh server instance with a fresh in-memory waiter map over the
    // same database. The durable session must survive it.
    let (server_b, _event_rx, _gateway_rx) = make_server(pool.clone());

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp_custom::<Sha1>(
        TOTP_CODE_VALIDITY_PERIOD,
        TOTP_CODE_DIGITS,
        &secret,
        timestamp,
    );

    let response = server_b
        .legacy_mfa_finish(
            ClientMfaFinishRequest {
                token: token.clone(),
                code: Some(code),
                auth_pub_key: None,
            },
            device_info(),
        )
        .await
        .expect("finish should succeed after restart");
    assert_ne!(response.preshared_key, "");
}

// Device posture.

mod posture {
    use xguard_common::db::{
        NoId,
        models::{
            device_posture::{
                DevicePosture, DevicePostureOsRule, LocationPostures, OsType, PostureSnapshot,
            },
            polling_token::PollingToken,
        },
    };
    use xguard_proto::{
        client_types::{DevicePostureFacts, PostureConnectRequest, PostureOs},
        proxy::{CoreError, CoreErrorCode},
    };

    use super::*;
    use crate::posture::worker::reevaluate_location;

    /// A Linux policy requiring disk encryption, attached to `location_id`.
    async fn attach_policy(pool: &PgPool, location_id: Id, firewall_required: bool) -> Id {
        let mut conn = pool.acquire().await.unwrap();
        let posture = DevicePosture {
            id: NoId,
            name: "Laptops".into(),
            description: None,
            min_desktop_client_version: Some("2.2.0".into()),
            min_mobile_client_version: None,
            allow_prerelease_client: false,
        }
        .save(&mut conn)
        .await
        .unwrap();
        set_rules(pool, &posture, firewall_required).await;
        LocationPostures::set(&mut conn, location_id, &[posture.id])
            .await
            .unwrap();
        posture.id
    }

    async fn set_rules(pool: &PgPool, posture: &DevicePosture<Id>, firewall_required: bool) {
        let mut conn = pool.acquire().await.unwrap();
        posture
            .replace_rules(
                &mut conn,
                &[DevicePostureOsRule {
                    posture_id: posture.id,
                    os_type: OsType::Linux,
                    min_kernel_version: Some("6.1".into()),
                    disk_encryption_required: Some(true),
                    firewall_required: Some(firewall_required),
                    ..Default::default()
                }],
            )
            .await
            .unwrap();
    }

    fn facts(disk_encrypted: bool) -> DevicePostureFacts {
        DevicePostureFacts {
            os: PostureOs::Linux as i32,
            os_version: Some("24.04".into()),
            kernel_version: Some("6.8.0-45-generic".into()),
            client_version: "2.2.0".into(),
            disk_encrypted: Some(disk_encrypted),
            firewall_enabled: Some(false),
            collected_at: Utc::now().timestamp(),
            ..Default::default()
        }
    }

    fn posture_event(event: BidiStreamEvent) -> DesktopClientMfaEvent {
        match event.event {
            BidiStreamEventType::DesktopClientMfa(event) => *event,
            other => panic!("unexpected event {other:?}"),
        }
    }

    fn rejected(status: &tonic::Status, reason: &str) {
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        assert!(
            status
                .message()
                .starts_with("Device posture check failed: "),
            "{status:?}"
        );
        assert!(status.message().contains(reason), "{status:?}");
        let error = CoreError::from(status.clone());
        assert_eq!(error.code(), CoreErrorCode::PostureRejected);
    }

    #[sqlx::test]
    async fn test_posture_checked_at_mfa_start(_: PgPoolOptions, options: PgConnectOptions) {
        let pool = setup_pool(options).await;
        initialize_current_settings(&pool).await.unwrap();
        let location = create_mfa_location(&pool).await;
        create_and_assign_mfa_flow(&pool, location.id).await;
        let mut user = create_user(&pool).await;
        let secret = vec![7u8; 10];
        user.totp_secret = Some(secret.clone());
        user.totp_enabled = true;
        user.save(&pool).await.unwrap();
        let device = create_device(&pool, user.id).await;
        attach_device_to_location(&pool, location.id, device.id).await;
        attach_policy(&pool, location.id, false).await;
        let (server, mut event_rx, _gateway_rx) = make_server(pool.clone());

        let start = |posture: Option<DevicePostureFacts>| ClientMfaStartRequest {
            location_id: location.id,
            pubkey: device.wireguard_pubkey.clone(),
            method: MfaMethod::Totp as i32,
            posture,
        };

        // Old clients send nothing: refused before emitting events or writing snapshots.
        let Err(MfaStartRejection::Status(status)) =
            server.legacy_mfa_start(start(None), device_info()).await
        else {
            panic!("a device without posture must be refused");
        };
        rejected(&status, "did not report device posture");
        assert!(event_rx.try_recv().is_err());
        assert!(
            PostureSnapshot::find(&pool, device.id)
                .await
                .unwrap()
                .is_none()
        );

        // Non-compliant facts: refused without unauthenticated snapshot overwrite or event spam.
        let Err(MfaStartRejection::Status(status)) = server
            .legacy_mfa_start(start(Some(facts(false))), device_info())
            .await
        else {
            panic!("an unencrypted device must be refused");
        };
        rejected(&status, "disk encryption is required");
        assert!(event_rx.try_recv().is_err());
        assert!(
            PostureSnapshot::find(&pool, device.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            VpnClientMfaSession::<Id>::find_active_by_token(&pool, "none")
                .await
                .unwrap()
                .is_none()
        );

        // The same for the multi-step contract.
        let Err(MfaStartRejection::Status(status)) = server
            .mfa_flow_start(
                MfaFlowStartRequest {
                    location_id: location.id,
                    pubkey: device.wireguard_pubkey.clone(),
                    selected_methods: vec![MfaMethod::Totp as i32],
                    posture: Some(facts(false)),
                },
                device_info(),
            )
            .await
        else {
            panic!("an unencrypted device must be refused");
        };
        rejected(&status, "disk encryption is required");
        assert!(event_rx.try_recv().is_err());

        // Compliant facts: MFA starts; snapshot and event are deferred until finish succeeds.
        let started = server
            .legacy_mfa_start(start(Some(facts(true))), device_info())
            .await
            .unwrap_or_else(|_| panic!("a compliant device starts MFA"));
        assert!(event_rx.try_recv().is_err());
        assert!(
            PostureSnapshot::find(&pool, device.id)
                .await
                .unwrap()
                .is_none()
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp_custom::<Sha1>(TOTP_CODE_VALIDITY_PERIOD, TOTP_CODE_DIGITS, &secret, now);
        server
            .legacy_mfa_finish(
                ClientMfaFinishRequest {
                    token: started.token,
                    code: Some(code),
                    auth_pub_key: None,
                },
                device_info(),
            )
            .await
            .unwrap();
        assert!(matches!(
            posture_event(event_rx.try_recv().unwrap()),
            DesktopClientMfaEvent::PostureCheckPassed { .. }
        ));
        let snapshot = PostureSnapshot::find(&pool, device.id)
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.compliant);
        assert!(snapshot.failed_checks.is_empty());
        assert_eq!(snapshot.location_id, Some(location.id));
    }

    #[sqlx::test]
    async fn test_mfa_completion_rechecks_posture(_: PgPoolOptions, options: PgConnectOptions) {
        let pool = setup_pool(options).await;
        initialize_current_settings(&pool).await.unwrap();
        let location = create_mfa_location(&pool).await;
        create_and_assign_mfa_flow(&pool, location.id).await;
        let mut user = create_user(&pool).await;
        let secret = vec![7u8; 10];
        user.totp_secret = Some(secret.clone());
        user.totp_enabled = true;
        user.save(&pool).await.unwrap();
        let device = create_device(&pool, user.id).await;
        attach_device_to_location(&pool, location.id, device.id).await;
        let posture_id = attach_policy(&pool, location.id, false).await;
        let (server, _event_rx, mut gateway_rx) = make_server(pool.clone());

        let code = || {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            totp_custom::<Sha1>(TOTP_CODE_VALIDITY_PERIOD, TOTP_CODE_DIGITS, &secret, now)
        };
        let start = || async {
            server
                .legacy_mfa_start(
                    ClientMfaStartRequest {
                        location_id: location.id,
                        pubkey: device.wireguard_pubkey.clone(),
                        method: MfaMethod::Totp as i32,
                        posture: Some(facts(true)),
                    },
                    device_info(),
                )
                .await
                .unwrap_or_else(|_| panic!("start"))
                .token
        };

        // The policy gets stricter while the user types the code: no session is authorized.
        let token = start().await;
        let posture = DevicePosture::find_by_id(&pool, posture_id)
            .await
            .unwrap()
            .unwrap();
        set_rules(&pool, &posture, true).await;
        let status = server
            .legacy_mfa_finish(
                ClientMfaFinishRequest {
                    token,
                    code: Some(code()),
                    auth_pub_key: None,
                },
                device_info(),
            )
            .await
            .err()
            .expect("a device that no longer complies must not be authorized");
        rejected(&status, "firewall is required");
        assert!(
            VpnClientSession::get_all_active_device_sessions_in_location(
                &pool,
                location.id,
                device.id
            )
            .await
            .unwrap()
            .is_empty()
        );
        assert!(gateway_rx.try_recv().is_err());

        // A stale report is not accepted either.
        set_rules(&pool, &posture, false).await;
        let token = start().await;
        sqlx::query(
            "UPDATE vpn_client_mfa_session SET created_at = created_at - interval '1 hour'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let status = server
            .legacy_mfa_finish(
                ClientMfaFinishRequest {
                    token,
                    code: Some(code()),
                    auth_pub_key: None,
                },
                device_info(),
            )
            .await
            .err()
            .expect("a stale posture report must not be accepted");
        rejected(&status, "too old");
    }

    #[sqlx::test]
    async fn test_posture_only_connect(_: PgPoolOptions, options: PgConnectOptions) {
        let pool = setup_pool(options).await;
        initialize_current_settings(&pool).await.unwrap();
        let mut location = create_mfa_location(&pool).await;
        location.mfa_enabled = false;
        location.save(&pool).await.unwrap();
        let user = create_user(&pool).await;
        let device = create_device(&pool, user.id).await;
        attach_device_to_location(&pool, location.id, device.id).await;
        let token = {
            let (token, secret) = PollingToken::new(device.id);
            token.save(&pool).await.unwrap();
            secret
        };
        let (server, mut event_rx, mut gateway_rx) = make_server(pool.clone());
        let request = |token: &str, pubkey: &str, disk_encrypted: bool| PostureConnectRequest {
            location_id: location.id,
            pubkey: pubkey.into(),
            token: token.into(),
            posture: Some(facts(disk_encrypted)),
        };

        // Without posture policies the key is empty and no session is created.
        let response = server
            .posture_connect(
                request(&token, &device.wireguard_pubkey, false),
                device_info(),
            )
            .await
            .unwrap();
        assert!(response.preshared_key.is_empty());
        attach_policy(&pool, location.id, false).await;

        // The caller must hold the device's polling token.
        for (token, pubkey) in [
            ("wrong-token", device.wireguard_pubkey.as_str()),
            ("", device.wireguard_pubkey.as_str()),
            (token.as_str(), "unknown-pubkey"),
        ] {
            let status = server
                .posture_connect(request(token, pubkey, true), device_info())
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::Unauthenticated, "{token} {pubkey}");
        }
        assert!(event_rx.try_recv().is_err());

        // Non-compliant: refused.
        let status = server
            .posture_connect(
                request(&token, &device.wireguard_pubkey, false),
                device_info(),
            )
            .await
            .unwrap_err();
        rejected(&status, "disk encryption is required");
        assert!(matches!(
            posture_event(event_rx.try_recv().unwrap()),
            DesktopClientMfaEvent::PostureCheckFailed { .. }
        ));

        // Compliant: a session with a fresh key is authorized on the gateway.
        let response = server
            .posture_connect(
                request(&token, &device.wireguard_pubkey, true),
                device_info(),
            )
            .await
            .unwrap();
        assert!(!response.preshared_key.is_empty());
        let sessions = VpnClientSession::get_all_active_device_sessions_in_location(
            &pool,
            location.id,
            device.id,
        )
        .await
        .unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(!sessions[0].is_mfa_session);
        let mut authorized = false;
        while let Ok(command) = gateway_rx.try_recv() {
            if let GatewayCommand::VpnSessionAuthorized(id, authorized_device, info) = command {
                assert_eq!(id, location.id);
                assert_eq!(authorized_device.id, device.id);
                assert_eq!(
                    info.preshared_key
                        .as_ref()
                        .map(|k| k.expose_secret().to_string()),
                    Some(response.preshared_key.clone())
                );
                authorized = true;
            }
        }
        assert!(authorized);

        // A location with MFA takes posture during MFA instead.
        location.mfa_enabled = true;
        location.save(&pool).await.unwrap();
        let status = server
            .posture_connect(
                request(&token, &device.wireguard_pubkey, true),
                device_info(),
            )
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[sqlx::test]
    async fn test_policy_change_disconnects_non_compliant_sessions(
        _: PgPoolOptions,
        options: PgConnectOptions,
    ) {
        let pool = setup_pool(options).await;
        initialize_current_settings(&pool).await.unwrap();
        let mut location = create_mfa_location(&pool).await;
        location.mfa_enabled = false;
        location.save(&pool).await.unwrap();
        let user = create_user(&pool).await;
        let device = create_device(&pool, user.id).await;
        attach_device_to_location(&pool, location.id, device.id).await;
        let token = {
            let (token, secret) = PollingToken::new(device.id);
            token.save(&pool).await.unwrap();
            secret
        };
        let posture_id = attach_policy(&pool, location.id, false).await;
        let (server, mut event_rx, mut gateway_rx) = make_server(pool.clone());
        server
            .posture_connect(
                PostureConnectRequest {
                    location_id: location.id,
                    pubkey: device.wireguard_pubkey.clone(),
                    token,
                    posture: Some(facts(true)),
                },
                device_info(),
            )
            .await
            .unwrap();
        while event_rx.try_recv().is_ok() {}
        while gateway_rx.try_recv().is_ok() {}

        let (gateway_tx, mut worker_gateway_rx) = mpsc::unbounded_channel();
        let (bidi_tx, mut worker_event_rx) = mpsc::unbounded_channel();
        let channels = EventChannels::new(gateway_tx, bidi_tx);

        // Unchanged policy: the device still complies.
        assert_eq!(
            reevaluate_location(&pool, &channels, location.id)
                .await
                .unwrap(),
            0
        );

        // Stricter policy: the stored report fails it, so the session is closed.
        let posture = DevicePosture::find_by_id(&pool, posture_id)
            .await
            .unwrap()
            .unwrap();
        set_rules(&pool, &posture, true).await;
        assert_eq!(
            reevaluate_location(&pool, &channels, location.id)
                .await
                .unwrap(),
            1
        );
        assert!(
            VpnClientSession::get_all_active_device_sessions_in_location(
                &pool,
                location.id,
                device.id
            )
            .await
            .unwrap()
            .is_empty()
        );
        let mut deauthorized = false;
        while let Ok(command) = worker_gateway_rx.try_recv() {
            if matches!(command, GatewayCommand::VpnSessionDeauthorized(id, ref d) if id == location.id && d.id == device.id)
            {
                deauthorized = true;
            }
        }
        assert!(deauthorized);
        let mut audited = false;
        while let Ok(event) = worker_event_rx.try_recv() {
            if let DesktopClientMfaEvent::PostureCheckFailed { failed_checks, .. } =
                posture_event(event)
            {
                assert_eq!(failed_checks, vec!["firewall is required"]);
                audited = true;
            }
        }
        assert!(audited);
        let snapshot = PostureSnapshot::find(&pool, device.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!snapshot.compliant);
    }
}
