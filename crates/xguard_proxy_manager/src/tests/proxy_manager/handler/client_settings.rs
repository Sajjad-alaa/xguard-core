//! Client settings over the Edge protocol: device creation through enrollment is refused when
//! only admins may manage devices, and the effective traffic policy, tunnel switch and group MTU
//! overrides reach the client in the instance info and device configs.

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use xguard_common::db::{
    Id,
    models::{
        ClientSettings, ClientTrafficPolicy, Device, User,
        client_settings::GroupClientTrafficPolicies, group::Group, wireguard::GroupClientMtu,
    },
    setup_pool,
};
use xguard_proto::{
    client_types::{
        ClientTrafficPolicy as WirePolicy, EnrollmentStartRequest, EnrollmentStartResponse,
        ExistingDevice, NewDevice,
    },
    proxy::{CoreRequest, core_request, core_response},
};

use super::support::{
    assert_device_config_response, assert_error_response_details, complete_proxy_handshake,
    create_enrollment_token, create_network, create_user, make_device_info,
};
use crate::tests::common::HandlerTestContext;

async fn save_settings(pool: &PgPool, settings: ClientSettings) {
    settings
        .save(pool)
        .await
        .expect("failed to save client settings");
}

async fn make_admin(pool: &PgPool, user: &User<Id>) {
    let admin_group = Group::find_by_name(pool, "admin")
        .await
        .unwrap()
        .expect("admin group exists");
    user.add_to_group(pool, &admin_group).await.unwrap();
}

async fn start(context: &mut HandlerTestContext, id: u64, token: &str) -> EnrollmentStartResponse {
    context.mock_proxy().send_request(CoreRequest {
        id,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::EnrollmentStart(
            EnrollmentStartRequest {
                token: token.to_owned(),
            },
        )),
    });
    match context.mock_proxy_mut().recv_outbound().await.payload {
        Some(core_response::Payload::EnrollmentStart(response)) => response,
        other => panic!(
            "expected EnrollmentStart, got {:?}",
            other.as_ref().map(std::mem::discriminant)
        ),
    }
}

fn new_device(id: u64, token: &str, pubkey: &str) -> CoreRequest {
    CoreRequest {
        id,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::NewDevice(NewDevice {
            name: format!("device-{id}"),
            pubkey: pubkey.to_owned(),
            token: Some(token.to_owned()),
        })),
    }
}

/// A self-issued token cannot create a device while only admins manage devices; the client is
/// told up front to skip the VPN step.
#[sqlx::test]
async fn test_enrollment_refuses_device_for_user_initiated_token(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let _network = create_network(&context.pool).await;
    save_settings(
        &context.pool,
        ClientSettings {
            admin_device_management: true,
            only_client_activation: true,
            ..ClientSettings::default()
        },
    )
    .await;

    let user = create_user(&context.pool).await;
    let token = create_enrollment_token(&context.pool, user.id, Some(user.id)).await;
    let started = start(&mut context, 1, &token.id).await;
    let settings = started.settings.expect("enrollment settings");
    assert!(settings.admin_device_management);
    assert!(settings.only_client_activation);

    let pubkey = "AA0aJzRBTltodYKPnKm2w9Dd6vcEER4rOEVSX2x5hpM=";
    context
        .mock_proxy()
        .send_request(new_device(2, &token.id, pubkey));
    let response = context.mock_proxy_mut().recv_outbound().await;
    let (code, message) = assert_error_response_details(&response);
    assert_eq!(code, tonic::Code::PermissionDenied);
    assert!(message.contains("administrators"), "{message}");
    assert!(
        Device::find_by_pubkey(&context.pool, pubkey)
            .await
            .unwrap()
            .is_none(),
        "no device may be created"
    );

    context.finish().await.expect_server_finished().await;
}

/// A token issued by an admin, or a token of an admin, may create a device.
#[sqlx::test]
async fn test_enrollment_allows_admin_initiated_device(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let _network = create_network(&context.pool).await;
    save_settings(
        &context.pool,
        ClientSettings {
            admin_device_management: true,
            ..ClientSettings::default()
        },
    )
    .await;

    let admin = create_user(&context.pool).await;
    make_admin(&context.pool, &admin).await;
    let user = create_user(&context.pool).await;
    let token = create_enrollment_token(&context.pool, user.id, Some(admin.id)).await;
    let started = start(&mut context, 1, &token.id).await;
    assert!(!started.settings.unwrap().admin_device_management);
    context.mock_proxy().send_request(new_device(
        2,
        &token.id,
        "BB1bKzSCUmupeZLQnLn3x0Ee7wfGF5sROR0WY3y6iqM=",
    ));
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert_device_config_response(&response);

    // An admin enrolling their own device.
    let token = create_enrollment_token(&context.pool, admin.id, Some(admin.id)).await;
    start(&mut context, 3, &token.id).await;
    context.mock_proxy().send_request(new_device(
        4,
        &token.id,
        "rfMv49t7ZXWo09zfXjKMFfkVRRZDyYkn4KRNHNe1X/k=",
    ));
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert_device_config_response(&response);

    // A token from someone who is no longer an admin counts as user-initiated.
    let former_admin = create_user(&context.pool).await;
    let token = create_enrollment_token(&context.pool, user.id, Some(former_admin.id)).await;
    let started = start(&mut context, 5, &token.id).await;
    assert!(started.settings.unwrap().admin_device_management);

    context.finish().await.expect_server_finished().await;
}

/// The effective traffic policy, the tunnel switch and the user's group MTU override reach the
/// client, on enrollment and on refresh.
#[sqlx::test]
async fn test_client_receives_effective_policy_and_group_mtu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let pool = context.pool.clone();
    let mut network = create_network(&pool).await;
    network.client_mtu = Some(1400);
    network.save(&pool).await.unwrap();
    let other = create_network(&pool).await;

    let restricted = Group::new("restricted").save(&pool).await.unwrap();
    let user = create_user(&pool).await;
    user.add_to_group(&pool, &restricted).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    network
        .set_group_client_mtus(
            &mut conn,
            &[GroupClientMtu {
                client_mtu: 1280,
                group_ids: vec![restricted.id],
            }],
        )
        .await
        .unwrap();
    drop(conn);

    save_settings(
        &pool,
        ClientSettings {
            client_traffic_policy: ClientTrafficPolicy::ForceAllTraffic,
            disable_tunnels: true,
            ..ClientSettings::default()
        },
    )
    .await;

    let token = create_enrollment_token(&pool, user.id, Some(user.id)).await;
    let started = start(&mut context, 1, &token.id).await;
    let instance = started.instance.unwrap();
    assert_eq!(
        instance.client_traffic_policy,
        Some(WirePolicy::ForceAllTraffic as i32)
    );
    assert_eq!(instance.disable_tunnels, Some(true));

    let pubkey = "M94qhg9soHgFSsigRLXGsePFV6wPzyMavSaBpFsH1uM=";
    context
        .mock_proxy()
        .send_request(new_device(2, &token.id, pubkey));
    let response = context.mock_proxy_mut().recv_outbound().await;
    let config = assert_device_config_response(&response);
    let mtu_of = |id| {
        config
            .configs
            .iter()
            .find(|config| config.network_id == id)
            .expect("config for location")
            .mtu
    };
    assert_eq!(mtu_of(network.id), Some(1280), "group override wins");
    assert_eq!(mtu_of(other.id), None, "no override, no location MTU");

    // A group override replaces the instance default; refreshing sends the new policy.
    let mut conn = pool.acquire().await.unwrap();
    GroupClientTrafficPolicies {
        disable_all_traffic: vec![restricted.id],
        ..GroupClientTrafficPolicies::default()
    }
    .replace_all(&mut conn)
    .await
    .unwrap();
    drop(conn);

    let token = create_enrollment_token(&pool, user.id, Some(user.id)).await;
    start(&mut context, 3, &token.id).await;
    context.mock_proxy().send_request(CoreRequest {
        id: 4,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::ExistingDevice(ExistingDevice {
            pubkey: pubkey.to_owned(),
            token: Some(token.id.clone()),
        })),
    });
    let response = context.mock_proxy_mut().recv_outbound().await;
    let refreshed = assert_device_config_response(&response);
    let instance = refreshed.instance.as_ref().unwrap();
    assert_eq!(
        instance.client_traffic_policy,
        Some(WirePolicy::DisableAllTraffic as i32)
    );
    #[allow(deprecated)]
    let legacy = instance.disable_all_traffic;
    assert!(legacy, "older clients read the deprecated flag");

    context.finish().await.expect_server_finished().await;
}

/// The Edge receives the admin's display choices when it connects.
#[sqlx::test]
async fn test_edge_receives_display_flags_on_connect(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options.clone()).await;
    save_settings(
        &pool,
        ClientSettings {
            display_download_step: false,
            ..ClientSettings::default()
        },
    )
    .await;

    let mut context = HandlerTestContext::new(options).await;
    let response = context.mock_proxy_mut().recv_outbound().await;
    assert!(matches!(
        response.payload,
        Some(core_response::Payload::InitialInfo(_))
    ));
    match context.mock_proxy_mut().recv_public_settings().await {
        core_response::Payload::PublicSettings(settings) => {
            assert!(!settings.display_download_step);
            // No SMTP in tests, so password reset stays hidden.
            assert!(!settings.display_password_reset);
        }
        _ => unreachable!(),
    }
    context.finish().await.expect_server_finished().await;
}
