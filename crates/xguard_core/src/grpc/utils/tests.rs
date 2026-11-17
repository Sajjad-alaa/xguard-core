use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

use ipnetwork::IpNetwork;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tonic::Code;
use xguard_common::db::{
    Id,
    models::{
        Device, DeviceType, Settings, User, WireguardNetwork,
        biometric_auth::BiometricAuth,
        device::WireguardNetworkDevice,
        mfa_flow::{LocationMfaFlowAssignment, MfaFlow, MfaFlowStep},
        settings::{initialize_current_settings, update_current_settings},
        vpn_client_session::VpnClientMfaMethod,
        wireguard::ServiceLocationMode,
    },
    setup_pool,
};
use xguard_proto::{
    client_types::{DeviceConfig, LocationMfaMode, MfaMethod, MfaStep},
    proxy::DeviceInfo,
};

use super::{InstanceInfo, build_device_config_response, build_wire_steps};

const XGUARD_URL: &str = "http://localhost:8000";
const PROXY_URL: &str = "http://localhost:8080";

async fn init_settings(pool: &PgPool) {
    initialize_current_settings(pool)
        .await
        .expect("failed to init settings");
    let mut settings = Settings::get_current_settings();
    settings.xguard_url = XGUARD_URL.to_owned();
    settings.public_proxy_url = PROXY_URL.to_owned();
    update_current_settings(pool, settings)
        .await
        .expect("failed to update settings");
}

async fn create_user(pool: &PgPool) -> User<Id> {
    User::new(
        "mfa-gate-test",
        Some("pass123"),
        "Tester",
        "MfaGate",
        "mfa-gate@example.com",
        None,
    )
    .save(pool)
    .await
    .expect("failed to create user")
}

async fn create_device(pool: &PgPool, user_id: Id) -> Device<Id> {
    Device::new(
        "mfa-gate-device".to_owned(),
        "mfa-gate-pubkey".to_owned(),
        user_id,
        DeviceType::User,
        None,
        true,
    )
    .save(pool)
    .await
    .expect("failed to create device")
}

async fn create_network_device(pool: &PgPool, user_id: Id, name: &str, pubkey: &str) -> Device<Id> {
    Device::new(
        name.to_owned(),
        pubkey.to_owned(),
        user_id,
        DeviceType::Network,
        None,
        true,
    )
    .save(pool)
    .await
    .expect("failed to create network device")
}

/// Creates an MFA-enabled location with a single default flow built from `step_methods`.
async fn create_location(
    pool: &PgPool,
    name: &str,
    address_octet: u8,
    step_methods: Vec<Vec<VpnClientMfaMethod>>,
) -> WireguardNetwork<Id> {
    let network = WireguardNetwork::new(
        name.to_owned(),
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
    .set_address([IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 10, address_octet, 1)), 24).unwrap()])
    .expect("failed to set location address")
    .save(pool)
    .await
    .expect("failed to create location");

    let mut tx = pool.begin().await.expect("failed to begin tx");
    let (flow, _) = MfaFlow::create(&mut tx, format!("{name}-flow"), step_methods)
        .await
        .expect("failed to create flow");
    MfaFlow::assign_to_location(
        &mut tx,
        network.id,
        &[LocationMfaFlowAssignment {
            flow_id: flow.id,
            is_default: true,
            group_ids: Vec::new(),
        }],
    )
    .await
    .expect("failed to assign flow");
    tx.commit().await.expect("failed to commit tx");

    network
}

/// Creates an MFA-disabled location with no flow configured.
async fn create_disabled_location(
    pool: &PgPool,
    name: &str,
    address_octet: u8,
) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        name.to_owned(),
        51820,
        "vpn.example.com".to_owned(),
        None,
        [IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
        true,
        false,
        false,
        false,
        false, // mfa_enabled
        ServiceLocationMode::Disabled,
    )
    .set_address([IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 10, address_octet, 1)), 24).unwrap()])
    .expect("failed to set location address")
    .save(pool)
    .await
    .expect("failed to create location")
}

/// Creates an MFA-enabled location with no flow assigned (the transient
/// "MFA on, no policy built yet" state).
async fn create_mfa_location_without_flow(
    pool: &PgPool,
    name: &str,
    address_octet: u8,
) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        name.to_owned(),
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
    .set_address([IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 10, address_octet, 1)), 24).unwrap()])
    .expect("failed to set location address")
    .save(pool)
    .await
    .expect("failed to create location")
}

async fn attach_device(pool: &PgPool, location_id: Id, device_id: Id) {
    WireguardNetworkDevice::new(
        location_id,
        device_id,
        vec![IpAddr::V4(Ipv4Addr::new(10, 10, 0, 10))],
    )
    .insert(pool)
    .await
    .expect("failed to attach device");
}

fn device_info(version: &str) -> DeviceInfo {
    DeviceInfo {
        version: Some(version.to_owned()),
        ..Default::default()
    }
}

#[sqlx::test]
async fn test_polling_returns_only_attached_locations(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;

    let first = create_disabled_location(&pool, "attached-first", 1).await;
    let _unattached = create_mfa_location_without_flow(&pool, "unattached-mfa", 2).await;
    let last = create_disabled_location(&pool, "attached-last", 3).await;

    let response = build_device_config_response(&pool, device.clone(), None, None)
        .await
        .expect("failed to build config without attachments");
    assert_eq!(response.configs, [] as [DeviceConfig; 0]);

    attach_device(&pool, first.id, device.id).await;
    attach_device(&pool, last.id, device.id).await;
    let response = build_device_config_response(&pool, device, None, None)
        .await
        .expect("failed to build config with attachments");
    let mut names: Vec<&str> = response
        .configs
        .iter()
        .map(|config| config.network_name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["attached-first", "attached-last"]);
}

#[sqlx::test]
async fn test_multi_step_location_omitted_for_legacy_client(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;

    // Multi-step location: two steps, so `derive_legacy_mode` returns `None`.
    let multi_step = create_location(
        &pool,
        "multi-step-location",
        1,
        vec![
            vec![VpnClientMfaMethod::Totp],
            vec![VpnClientMfaMethod::Email],
        ],
    )
    .await;
    // Legacy-derivable location: single internal step, so `Some(Internal)`.
    let internal = create_location(
        &pool,
        "internal-location",
        2,
        vec![vec![
            VpnClientMfaMethod::Totp,
            VpnClientMfaMethod::Email,
            VpnClientMfaMethod::Biometric,
            VpnClientMfaMethod::MobileApprove,
        ]],
    )
    .await;
    attach_device(&pool, multi_step.id, device.id).await;
    attach_device(&pool, internal.id, device.id).await;

    // Legacy client (2.1.0): the multi-step location is omitted, the internal one retained.
    let response =
        build_device_config_response(&pool, device.clone(), None, Some(device_info("2.1.0")))
            .await
            .expect("failed to build config for legacy client");
    let names: Vec<&str> = response
        .configs
        .iter()
        .map(|config| config.network_name.as_str())
        .collect();
    assert!(
        !names.contains(&"multi-step-location"),
        "multi-step location must be omitted for a legacy client, got: {names:?}"
    );
    assert!(
        names.contains(&"internal-location"),
        "legacy-derivable location must be retained, got: {names:?}"
    );

    // Capable client (2.2.0): both locations are retained.
    let response =
        build_device_config_response(&pool, device.clone(), None, Some(device_info("2.2.0")))
            .await
            .expect("failed to build config for capable client");
    let names: Vec<&str> = response
        .configs
        .iter()
        .map(|config| config.network_name.as_str())
        .collect();
    assert!(
        names.contains(&"multi-step-location"),
        "multi-step location must be retained for a capable client, got: {names:?}"
    );
    assert!(
        names.contains(&"internal-location"),
        "legacy-derivable location must be retained, got: {names:?}"
    );
}

#[sqlx::test]
#[allow(deprecated)]
async fn test_multi_step_locations_sent_without_license(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;

    // XGuard has no license tiers: multi-step locations are sent like single-step ones.
    let single_step = create_location(
        &pool,
        "single-step-location",
        1,
        vec![vec![VpnClientMfaMethod::Totp]],
    )
    .await;
    let multi_step = create_location(
        &pool,
        "multi-step-location",
        2,
        vec![
            vec![VpnClientMfaMethod::Totp],
            vec![VpnClientMfaMethod::Email],
        ],
    )
    .await;
    attach_device(&pool, single_step.id, device.id).await;
    attach_device(&pool, multi_step.id, device.id).await;

    let response = build_device_config_response(&pool, device, None, Some(device_info("2.2.0")))
        .await
        .expect("failed to build config for capable client");
    let names: Vec<&str> = response
        .configs
        .iter()
        .map(|config| config.network_name.as_str())
        .collect();
    assert_eq!(names, vec!["single-step-location", "multi-step-location"]);
    let config = &response.configs[0];
    assert_eq!(config.location_mfa_mode, None);
    assert_eq!(config.steps.len(), 1);
}

#[sqlx::test]
async fn test_network_device_rejected_on_mfa_locations(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;

    // Multi-step location: a network device must be rejected.
    let multi_step = create_location(
        &pool,
        "multi-step-location",
        1,
        vec![
            vec![VpnClientMfaMethod::Totp],
            vec![VpnClientMfaMethod::Email],
        ],
    )
    .await;
    let multi_step_device =
        create_network_device(&pool, user.id, "multi-step-device", "multi-step-pubkey").await;
    attach_device(&pool, multi_step.id, multi_step_device.id).await;

    let error = build_device_config_response(&pool, multi_step_device, None, None)
        .await
        .err()
        .expect("network device on multi-step location should be rejected");
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "network devices cannot connect to locations with MFA enabled"
    );

    // Legacy-derivable (internal) location: also rejected, since a network device cannot
    // perform any MFA.
    let internal = create_location(
        &pool,
        "internal-location",
        2,
        vec![vec![
            VpnClientMfaMethod::Totp,
            VpnClientMfaMethod::Email,
            VpnClientMfaMethod::Biometric,
            VpnClientMfaMethod::MobileApprove,
        ]],
    )
    .await;
    let internal_device =
        create_network_device(&pool, user.id, "internal-device", "internal-pubkey").await;
    attach_device(&pool, internal.id, internal_device.id).await;

    let error = build_device_config_response(&pool, internal_device, None, None)
        .await
        .err()
        .expect("network device on legacy-derivable location should be rejected");
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "network devices cannot connect to locations with MFA enabled"
    );

    // MFA-disabled location: the config is still produced.
    let disabled = create_disabled_location(&pool, "disabled-location", 3).await;
    let disabled_device =
        create_network_device(&pool, user.id, "disabled-device", "disabled-pubkey").await;
    attach_device(&pool, disabled.id, disabled_device.id).await;

    let response = build_device_config_response(&pool, disabled_device, None, None)
        .await
        .expect("network device on MFA-disabled location should get config");
    assert_eq!(response.configs.len(), 1);
    assert_eq!(response.configs[0].network_name, "disabled-location");
}

/// Asserts every cell of the per-client-version config-shape matrix: four location
/// configurations across a legacy (2.1.0) and a capable (2.2.0) client.
#[sqlx::test]
#[allow(deprecated)]
async fn test_device_config_matrix(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let mut user = create_user(&pool).await;
    user.totp_enabled = true;
    user.save(&pool).await.expect("failed to configure TOTP");
    let device = create_device(&pool, user.id).await;

    let disabled = create_disabled_location(&pool, "disabled-location", 1).await;
    let internal = create_location(
        &pool,
        "internal-location",
        2,
        vec![vec![
            VpnClientMfaMethod::Totp,
            VpnClientMfaMethod::Email,
            VpnClientMfaMethod::Biometric,
            VpnClientMfaMethod::MobileApprove,
        ]],
    )
    .await;
    let external = create_location(
        &pool,
        "external-location",
        3,
        vec![vec![VpnClientMfaMethod::Oidc]],
    )
    .await;
    let multi_step = create_location(
        &pool,
        "multi-step-location",
        4,
        vec![
            vec![VpnClientMfaMethod::Totp],
            vec![VpnClientMfaMethod::Email],
        ],
    )
    .await;

    attach_device(&pool, disabled.id, device.id).await;
    attach_device(&pool, internal.id, device.id).await;
    attach_device(&pool, external.id, device.id).await;
    attach_device(&pool, multi_step.id, device.id).await;

    // Legacy client (2.1.0): multi-step location omitted; others carry `location_mfa_mode`
    // and no `steps`.
    let response =
        build_device_config_response(&pool, device.clone(), None, Some(device_info("2.1.0")))
            .await
            .expect("failed to build config for legacy client");
    let names: Vec<&str> = response
        .configs
        .iter()
        .map(|config| config.network_name.as_str())
        .collect();
    assert!(
        !names.contains(&"multi-step-location"),
        "multi-step location must be omitted for a legacy client, got: {names:?}"
    );

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "disabled-location")
        .expect("disabled location must be present");
    assert!(!config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::Disabled as i32)
    );
    assert_eq!(config.steps, [] as [xguard_proto::client_types::MfaStep; 0]);

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "internal-location")
        .expect("internal location must be present");
    assert!(config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::Internal as i32)
    );
    assert_eq!(config.steps, [] as [MfaStep; 0]);

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "external-location")
        .expect("external location must be present");
    assert!(config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::External as i32)
    );
    assert_eq!(config.steps, [] as [MfaStep; 0]);

    // Capable client (2.2.0): every location present; `location_mfa_mode` carries the
    // derived value (same as legacy) and `steps` is populated from the resolved flow.
    let response =
        build_device_config_response(&pool, device.clone(), None, Some(device_info("2.2.0")))
            .await
            .expect("failed to build config for capable client");

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "disabled-location")
        .expect("disabled location must be present");
    assert!(!config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::Disabled as i32)
    );
    assert_eq!(config.steps, [] as [MfaStep; 0]);

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "internal-location")
        .expect("internal location must be present");
    assert!(config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::Internal as i32)
    );
    assert_eq!(config.steps.len(), 1);
    assert_eq!(config.steps[0].methods.len(), 4);

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "external-location")
        .expect("external location must be present");
    assert!(config.mfa_enabled);
    assert_eq!(
        config.location_mfa_mode,
        Some(LocationMfaMode::External as i32)
    );
    assert_eq!(config.steps.len(), 1);
    // The OIDC-only step offers OIDC, not configured for this unlinked user.
    assert_eq!(config.steps[0].methods.len(), 1);
    assert_eq!(config.steps[0].methods[0].method, MfaMethod::Oidc as i32);
    assert!(!config.steps[0].methods[0].configured);

    let config = response
        .configs
        .iter()
        .find(|config| config.network_name == "multi-step-location")
        .expect("multi-step location must be present for a capable client");
    assert!(config.mfa_enabled);
    assert_eq!(config.location_mfa_mode, None);
    assert_eq!(config.steps.len(), 2);
    assert_eq!(config.steps[0].methods.len(), 1);
    assert_eq!(config.steps[1].methods.len(), 1);

    let mfa_user_state = response
        .instance
        .as_ref()
        .and_then(|instance| instance.mfa_user_state.as_ref())
        .expect("InstanceInfo should contain MFA user state");
    assert!(
        mfa_user_state
            .configured_methods
            .contains(&(MfaMethod::Totp as i32))
    );
    for name in ["internal-location", "multi-step-location"] {
        let config = response
            .configs
            .iter()
            .find(|config| config.network_name == name)
            .expect("MFA location must be present");
        let totp = config
            .steps
            .iter()
            .flat_map(|step| &step.methods)
            .find(|method| method.method == MfaMethod::Totp as i32)
            .expect("TOTP method must be advertised");
        assert!(totp.configured, "TOTP should be configured in {name}");
    }
}

/// An MFA-enabled location with no resolvable flow must fail closed for a capable client:
/// the config poll is rejected rather than advertising `steps = []`.
#[sqlx::test]
async fn test_mfa_enabled_location_without_flow_is_rejected(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;

    let no_flow = create_mfa_location_without_flow(&pool, "no-flow-location", 1).await;
    attach_device(&pool, no_flow.id, device.id).await;

    // Capable client (2.2.0): the no-flow location must be rejected.
    let error = build_device_config_response(&pool, device, None, Some(device_info("2.2.0")))
        .await
        .err()
        .expect("MFA-enabled location without a flow must be rejected");
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error.message().contains("no MFA flow is configured"),
        "unexpected message: {}",
        error.message()
    );
}

/// The wire `steps` carry each method's `configured` flag for the user's own setup, not just
/// the method list: setup state AND deployment availability gate it.
#[sqlx::test]
async fn test_build_wire_steps_computes_configured_flags(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;

    let mut user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;

    // User setup: TOTP enabled, email not set up, OIDC identity present, biometric
    // registered on this device (which also makes mobile-approve available).
    user.totp_enabled = true;
    user.openid_sub = Some("oidc-sub".to_owned());
    BiometricAuth::new(device.id, "biometric-pubkey".to_owned())
        .save(&pool)
        .await
        .expect("failed to save biometric auth");

    // A two-step flow covering all five methods.
    let mut tx = pool.begin().await.expect("failed to begin tx");
    let (_, steps) = MfaFlow::create(
        &mut tx,
        "wire-steps-flow".to_owned(),
        vec![
            vec![VpnClientMfaMethod::Totp, VpnClientMfaMethod::Email],
            vec![
                VpnClientMfaMethod::Oidc,
                VpnClientMfaMethod::Biometric,
                VpnClientMfaMethod::MobileApprove,
            ],
        ],
    )
    .await
    .expect("failed to create flow");
    tx.commit().await.expect("failed to commit tx");

    // Email is not set up for the user; OIDC has no provider.
    let settings = Settings::get_current_settings();
    let instance_info = InstanceInfo::build(&pool, &settings, &user, Some(device.id))
        .await
        .expect("failed to build instance info");
    let wire = build_wire_steps(&steps, &instance_info.configured_methods);

    assert_eq!(wire.len(), 2);

    assert_eq!(wire[0].methods.len(), 2);
    assert_eq!(wire[0].methods[0].method, MfaMethod::Totp as i32);
    assert!(wire[0].methods[0].configured);
    assert_eq!(wire[0].methods[1].method, MfaMethod::Email as i32);
    assert!(!wire[0].methods[1].configured);

    // OIDC is offered, but not configured while no provider is enabled.
    assert_eq!(wire[1].methods.len(), 3);
    assert_eq!(wire[1].methods[0].method, MfaMethod::Oidc as i32);
    assert!(!wire[1].methods[0].configured);
    assert_eq!(wire[1].methods[1].method, MfaMethod::Biometric as i32);
    assert!(wire[1].methods[1].configured);
    assert_eq!(wire[1].methods[2].method, MfaMethod::MobileApprove as i32);
    assert!(wire[1].methods[2].configured);

    let instance = xguard_proto::client_types::InstanceInfo::from(instance_info);
    let configured_from_instance = instance
        .mfa_user_state
        .expect("InstanceInfo should contain MFA user state")
        .configured_methods;
    let configured_from_steps = wire
        .iter()
        .flat_map(|step| &step.methods)
        .filter(|method| method.configured)
        .map(|method| method.method)
        .collect::<Vec<_>>();
    assert_eq!(configured_from_instance, configured_from_steps);
    assert_eq!(instance.openid_available, Some(false));

    // With an enabled provider, the linked user has OIDC configured.
    let mut conn = pool.acquire().await.unwrap();
    crate::sso::provider::ProviderConfig::save(
        &mut conn,
        crate::sso::provider::ProviderInput {
            kind: crate::sso::provider::ProviderKind::Okta,
            issuer: "http://localhost:9".into(),
            client_id: "client".into(),
            client_secret: Some("secret".into()),
            enabled: true,
            display_name: Some("Okta".into()),
            disable_password_management: false,
        },
    )
    .await
    .expect("failed to save provider");
    let instance_info = InstanceInfo::build(&pool, &settings, &user, Some(device.id))
        .await
        .expect("failed to build instance info");
    let wire = build_wire_steps(&steps, &instance_info.configured_methods);
    assert!(wire[1].methods[0].configured);
    let instance = xguard_proto::client_types::InstanceInfo::from(instance_info);
    assert_eq!(instance.openid_available, Some(true));
    assert_eq!(instance.openid_display_name.as_deref(), Some("Okta"));
    assert_eq!(
        instance.openid_provider_kind,
        Some(xguard_proto::client_types::OpenIdProviderKind::Okta as i32)
    );
}

#[test]
fn test_repeated_mfa_method_uses_same_configured_flag() {
    let steps = vec![
        MfaFlowStep {
            id: 1,
            flow_id: 1,
            position: 0,
            methods: HashSet::from([VpnClientMfaMethod::Totp, VpnClientMfaMethod::Email]),
        },
        MfaFlowStep {
            id: 2,
            flow_id: 1,
            position: 1,
            methods: HashSet::from([VpnClientMfaMethod::Totp, VpnClientMfaMethod::Biometric]),
        },
    ];
    let wire = build_wire_steps(&steps, &[VpnClientMfaMethod::Totp]);
    assert!(wire[0].methods[0].configured);
    assert!(!wire[0].methods[1].configured);
    assert!(wire[1].methods[0].configured);
    assert!(!wire[1].methods[1].configured);
}

#[sqlx::test]
async fn test_instance_info_without_device_id_excludes_biometric(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let device = create_device(&pool, user.id).await;
    BiometricAuth::new(device.id, "biometric-pubkey".to_owned())
        .save(&pool)
        .await
        .expect("failed to configure biometric authentication");

    let settings = Settings::get_current_settings();
    let instance = InstanceInfo::build(&pool, &settings, &user, None)
        .await
        .expect("failed to build instance info");
    assert!(
        !instance
            .configured_methods
            .contains(&VpnClientMfaMethod::Biometric)
    );
    assert!(
        instance
            .configured_methods
            .contains(&VpnClientMfaMethod::MobileApprove)
    );
}

#[sqlx::test]
async fn test_instance_info_has_empty_mfa_user_state_when_unconfigured(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let settings = Settings::get_current_settings();

    let instance: xguard_proto::client_types::InstanceInfo =
        InstanceInfo::build(&pool, &settings, &user, None)
            .await
            .expect("failed to build instance info")
            .into();

    assert_eq!(
        instance
            .mfa_user_state
            .expect("InstanceInfo should contain MFA user state")
            .configured_methods,
        [] as [i32; 0]
    );
}

#[sqlx::test]
async fn test_instance_info_advertises_smtp_and_openid_availability(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    init_settings(&pool).await;
    let user = create_user(&pool).await;
    let settings = Settings::get_current_settings();

    let instance: xguard_proto::client_types::InstanceInfo =
        InstanceInfo::build(&pool, &settings, &user, None)
            .await
            .expect("failed to build instance info")
            .into();

    assert_eq!(instance.smtp_configured, Some(false));
    assert_eq!(instance.openid_available, Some(false));
}
