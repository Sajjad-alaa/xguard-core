//! Device posture through the proxy bidi stream: posture-only connections and posture
//! refusals at MFA start reach Edge with their error code.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tonic::Code;
use xguard_common::db::{
    NoId,
    models::{
        device_posture::{DevicePosture, DevicePostureOsRule, LocationPostures, OsType},
        polling_token::PollingToken,
    },
};
use xguard_proto::{
    client_types::{
        ClientMfaStartRequest, DevicePostureFacts, MfaMethod, PostureConnectRequest, PostureOs,
    },
    proxy::{CoreErrorCode, CoreRequest, core_request, core_response},
};

use super::support::{
    assert_error_response_full, assert_vpn_session_exists, complete_proxy_handshake,
    create_mfa_network, create_network, create_user_with_device, make_device_info,
    setup_user_totp_mfa,
};
use crate::tests::common::HandlerTestContext;

async fn require_disk_encryption(pool: &sqlx::PgPool, location_id: i64) {
    let mut conn = pool.acquire().await.unwrap();
    let posture = DevicePosture {
        id: NoId,
        name: "Encrypted".into(),
        description: None,
        min_desktop_client_version: None,
        min_mobile_client_version: None,
        allow_prerelease_client: false,
    }
    .save(&mut conn)
    .await
    .unwrap();
    posture
        .replace_rules(
            &mut conn,
            &[DevicePostureOsRule {
                posture_id: posture.id,
                os_type: OsType::Linux,
                disk_encryption_required: Some(true),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    LocationPostures::set(&mut conn, location_id, &[posture.id])
        .await
        .unwrap();
}

fn facts(disk_encrypted: bool) -> DevicePostureFacts {
    DevicePostureFacts {
        os: PostureOs::Linux as i32,
        client_version: "2.2.0".into(),
        disk_encrypted: Some(disk_encrypted),
        ..Default::default()
    }
}

#[sqlx::test]
async fn test_posture_connect_through_bidi(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let network = create_network(&context.pool).await;
    let (_, device) = create_user_with_device(&context.pool).await;
    let token = PollingToken::new(device.id)
        .save(&context.pool)
        .await
        .unwrap()
        .token;
    require_disk_encryption(&context.pool, network.id).await;

    let request = |id, disk_encrypted| CoreRequest {
        id,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::PostureConnect(
            PostureConnectRequest {
                location_id: network.id,
                pubkey: device.wireguard_pubkey.clone(),
                token: token.clone(),
                posture: Some(facts(disk_encrypted)),
            },
        )),
    };

    context.mock_proxy().send_request(request(1, false));
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert_eq!(response.id, 1);
    let (code, message, error_code) = assert_error_response_full(&response);
    assert_eq!(code, Code::PermissionDenied);
    assert_eq!(error_code, CoreErrorCode::PostureRejected);
    assert!(message.contains("disk encryption is required"), "{message}");

    context.mock_proxy().send_request(request(2, true));
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert_eq!(response.id, 2);
    let Some(core_response::Payload::PostureConnect(connected)) = response.payload else {
        panic!("expected a PostureConnect response");
    };
    assert!(!connected.preshared_key.is_empty());
    assert_vpn_session_exists(&context.pool, network.id, device.id).await;

    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_mfa_start_posture_refusal_carries_code(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let network = create_mfa_network(&context.pool).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    setup_user_totp_mfa(&context.pool, &mut user).await;
    require_disk_encryption(&context.pool, network.id).await;

    context.mock_proxy().send_request(CoreRequest {
        id: 7,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::ClientMfaStart(
            ClientMfaStartRequest {
                location_id: network.id,
                pubkey: device.wireguard_pubkey.clone(),
                method: MfaMethod::Totp as i32,
                posture: Some(facts(false)),
            },
        )),
    });
    let response = context.mock_proxy_mut().recv_outbound().await;
    let (code, message, error_code) = assert_error_response_full(&response);
    assert_eq!(code, Code::PermissionDenied);
    assert_eq!(error_code, CoreErrorCode::PostureRejected);
    assert_eq!(
        message,
        "Device posture check failed: disk encryption is required"
    );

    context.finish().await.expect_server_finished().await;
}
