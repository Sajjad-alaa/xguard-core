//! Desktop client configuration sync over the Edge protocol (`InstanceInfo`): revisions and
//! `not_modified`, token checks and limits, client settings and service locations in the polled
//! configuration.

use std::time::Duration;

use base64::{Engine, prelude::BASE64_STANDARD};
use prost::Message;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tonic::Code;
use xguard_common::db::models::{
    ClientSettings, ClientTrafficPolicy, User,
    polling_token::{PollingToken, polling_token_digest},
    wireguard::ServiceLocationMode,
};
use xguard_proto::{
    client_types::{
        ClientPlatformInfo, ClientTrafficPolicy as WirePolicy, InstanceInfoRequest,
        InstanceInfoResponse, ServiceLocationMode as WireServiceLocationMode,
    },
    proxy::{CoreRequest, CoreResponse, DeviceInfo, core_request, core_response},
};

use super::support::{
    assert_error_response, complete_proxy_handshake, create_network, create_polling_token,
    create_user_with_device, make_device_info,
};
use crate::{
    servers::polling::{MAX_FAILURES_PER_WINDOW, MIN_DEVICE_POLL_INTERVAL},
    tests::common::HandlerTestContext,
};

fn linux_client(version: &str) -> DeviceInfo {
    let platform = ClientPlatformInfo {
        os_family: "unix".into(),
        os_type: "linux".into(),
        version: "24.04".into(),
        ..ClientPlatformInfo::default()
    };
    DeviceInfo {
        version: Some(version.into()),
        platform: Some(BASE64_STANDARD.encode(platform.encode_to_vec())),
        ..make_device_info()
    }
}

async fn poll_raw(
    context: &mut HandlerTestContext,
    id: u64,
    token: &str,
    revision: Option<&str>,
    device_info: DeviceInfo,
) -> CoreResponse {
    context.mock_proxy().send_request(CoreRequest {
        id,
        device_info: Some(device_info),
        payload: Some(core_request::Payload::InstanceInfo(InstanceInfoRequest {
            token: token.to_owned(),
            config_revision: revision.map(str::to_owned),
        })),
    });
    context.mock_proxy_mut().recv_outbound().await
}

async fn poll(
    context: &mut HandlerTestContext,
    id: u64,
    token: &str,
    revision: Option<&str>,
) -> InstanceInfoResponse {
    // Stay clear of the per-device limit.
    tokio::time::sleep(MIN_DEVICE_POLL_INTERVAL + Duration::from_millis(50)).await;
    let response = poll_raw(context, id, token, revision, linux_client("2.2.0")).await;
    match response.payload {
        Some(core_response::Payload::InstanceInfo(info)) => info,
        other => panic!(
            "expected InstanceInfo, got {:?}",
            other.as_ref().map(std::mem::discriminant)
        ),
    }
}

/// The first poll returns the configuration and its revision; polling again with that revision
/// answers `not_modified` without a configuration; a change produces a new revision.
#[sqlx::test]
async fn test_poll_revision_and_not_modified(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mut network = create_network(&context.pool).await;
    let (_, device) = create_user_with_device(&context.pool).await;
    let token = create_polling_token(&context.pool, device.id).await;

    let first = poll(&mut context, 1, &token, None).await;
    let revision = first.config_revision.clone().expect("revision");
    assert_eq!(first.not_modified, Some(false));
    assert!(first.poll_interval_secs.is_some_and(|secs| secs >= 30));
    let config = first.device_config.expect("device config");
    assert_eq!(config.configs.len(), 1);
    assert_eq!(config.configs[0].network_id, network.id);
    assert!(
        config.token.is_none(),
        "polling never hands out a new token"
    );

    let unchanged = poll(&mut context, 2, &token, Some(&revision)).await;
    assert_eq!(unchanged.not_modified, Some(true));
    assert!(unchanged.device_config.is_none());
    assert_eq!(
        unchanged.config_revision.as_deref(),
        Some(revision.as_str())
    );

    // An unknown or garbled revision gets the full configuration.
    let garbled = poll(&mut context, 3, &token, Some(&"x".repeat(500))).await;
    assert!(garbled.device_config.is_some());

    network.dns = Some("10.0.0.53".into());
    network.save(&context.pool).await.unwrap();
    let changed = poll(&mut context, 4, &token, Some(&revision)).await;
    assert_eq!(changed.not_modified, Some(false));
    assert_ne!(changed.config_revision.as_deref(), Some(revision.as_str()));
    let config = changed.device_config.expect("device config");
    assert_eq!(config.configs[0].dns.as_deref(), Some("10.0.0.53"));

    context.finish().await.expect_server_finished().await;
}

/// Unknown tokens are refused; too many from one address block that address for a while, even
/// with a valid token. Stored tokens are digests.
#[sqlx::test]
async fn test_poll_token_checks_and_failure_limit(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let _network = create_network(&context.pool).await;
    let (_, device) = create_user_with_device(&context.pool).await;
    let token = create_polling_token(&context.pool, device.id).await;

    let stored: String = sqlx::query_scalar("SELECT token FROM pollingtoken WHERE device_id = $1")
        .bind(device.id)
        .fetch_one(&context.pool)
        .await
        .unwrap();
    assert_ne!(stored, token, "the secret is not stored");
    assert_eq!(stored, polling_token_digest(&token));

    let other_address = DeviceInfo {
        ip_address: "192.0.2.10".into(),
        ..linux_client("2.2.0")
    };
    for id in 0..u64::from(MAX_FAILURES_PER_WINDOW) {
        let response = poll_raw(&mut context, id, "not-a-token", None, other_address.clone()).await;
        assert_eq!(assert_error_response(&response), Code::Unauthenticated);
    }
    let response = poll_raw(&mut context, 100, "", None, other_address.clone()).await;
    assert_eq!(assert_error_response(&response), Code::ResourceExhausted);
    let response = poll_raw(&mut context, 101, &token, None, other_address).await;
    assert_eq!(
        assert_error_response(&response),
        Code::ResourceExhausted,
        "a blocked address is refused before the token is looked up"
    );

    // Another address is not affected.
    let response = poll_raw(&mut context, 102, &token, None, linux_client("2.2.0")).await;
    assert!(matches!(
        response.payload,
        Some(core_response::Payload::InstanceInfo(_))
    ));

    context.finish().await.expect_server_finished().await;
}

/// A device polling too often is refused; a disabled user's device gets nothing.
#[sqlx::test]
async fn test_poll_device_rate_limit_and_disabled_user(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let _network = create_network(&context.pool).await;
    let (mut user, device) = create_user_with_device(&context.pool).await;
    let token = create_polling_token(&context.pool, device.id).await;

    let _ = poll(&mut context, 1, &token, None).await;
    let response = poll_raw(&mut context, 2, &token, None, linux_client("2.2.0")).await;
    assert_eq!(assert_error_response(&response), Code::ResourceExhausted);

    user.is_active = false;
    user.save(&context.pool).await.unwrap();
    tokio::time::sleep(MIN_DEVICE_POLL_INTERVAL + Duration::from_millis(50)).await;
    let response = poll_raw(&mut context, 3, &token, None, linux_client("2.2.0")).await;
    assert_eq!(assert_error_response(&response), Code::PermissionDenied);

    // A token whose device was removed no longer works.
    tokio::time::sleep(MIN_DEVICE_POLL_INTERVAL + Duration::from_millis(50)).await;
    PollingToken::delete_for_device_id(&context.pool, device.id)
        .await
        .unwrap();
    let response = poll_raw(&mut context, 4, &token, None, linux_client("2.2.0")).await;
    assert_eq!(assert_error_response(&response), Code::Unauthenticated);
    let _ = User::find_by_id(&context.pool, user.id).await.unwrap();

    context.finish().await.expect_server_finished().await;
}

/// Client settings reach a polling client: traffic policy, the tunnel switch and the MTU.
#[sqlx::test]
async fn test_poll_carries_client_settings(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mut network = create_network(&context.pool).await;
    let (_, device) = create_user_with_device(&context.pool).await;
    let token = create_polling_token(&context.pool, device.id).await;
    let before = poll(&mut context, 1, &token, None).await;
    let revision = before.config_revision.unwrap();

    ClientSettings {
        client_traffic_policy: ClientTrafficPolicy::DisableAllTraffic,
        disable_tunnels: true,
        ..ClientSettings::default()
    }
    .save(&context.pool)
    .await
    .unwrap();
    network.client_mtu = Some(1300);
    network.save(&context.pool).await.unwrap();

    let after = poll(&mut context, 2, &token, Some(&revision)).await;
    let config = after
        .device_config
        .expect("settings changed the configuration");
    let instance = config.instance.expect("instance info");
    assert_eq!(
        instance.client_traffic_policy,
        Some(WirePolicy::DisableAllTraffic as i32)
    );
    assert_eq!(instance.disable_tunnels, Some(true));
    assert_eq!(config.configs[0].mtu, Some(1300));

    context.finish().await.expect_server_finished().await;
}

/// Service locations reach clients that support them; locations combining service mode with MFA
/// (refused by the API, but possible in old rows) never do.
#[sqlx::test]
async fn test_poll_service_locations(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mut service = create_network(&context.pool).await;
    service.service_location_mode = ServiceLocationMode::AlwaysOn;
    service.save(&context.pool).await.unwrap();
    let mut with_mfa = create_network(&context.pool).await;
    with_mfa.service_location_mode = ServiceLocationMode::PreLogon;
    with_mfa.save(&context.pool).await.unwrap();
    let (_, device) = create_user_with_device(&context.pool).await;
    // MFA is switched on after the device joined, as an old row would have it.
    with_mfa.mfa_enabled = true;
    with_mfa.save(&context.pool).await.unwrap();
    let token = create_polling_token(&context.pool, device.id).await;

    let response = poll(&mut context, 1, &token, None).await;
    let configs = response.device_config.unwrap().configs;
    assert_eq!(configs.len(), 1, "{configs:?}");
    assert_eq!(configs[0].network_id, service.id);
    assert_eq!(
        configs[0].service_location_mode,
        Some(WireServiceLocationMode::Alwayson as i32)
    );

    // A client too old for service locations does not get them.
    tokio::time::sleep(MIN_DEVICE_POLL_INTERVAL + Duration::from_millis(50)).await;
    let response = poll_raw(&mut context, 2, &token, None, linux_client("2.0.0")).await;
    match response.payload {
        Some(core_response::Payload::InstanceInfo(info)) => {
            assert!(info.device_config.unwrap().configs.is_empty());
        }
        other => panic!(
            "expected InstanceInfo, got {:?}",
            other.as_ref().map(std::mem::discriminant)
        ),
    }

    context.finish().await.expect_server_finished().await;
}
