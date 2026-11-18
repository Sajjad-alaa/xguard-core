use std::{
    assert_matches,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::mpsc;
use xguard_common::db::{
    Id,
    models::{
        Device, WireguardNetwork,
        device::WireguardNetworkDevice,
        group::Group,
        wireguard::{
            DEFAULT_DISCONNECT_THRESHOLD, DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_WIREGUARD_MTU,
            ServiceLocationMode,
        },
    },
};
use xguard_core::{
    grpc::GatewayCommand,
    handlers::{Auth, GroupInfo, wireguard::WireguardNetworkData},
};

use super::common::{
    authenticate_admin, client::TestClient, fetch_user_details, make_network, make_test_client,
    setup_pool, update_location_mfa_flows,
};

const INVALID_MFA_PEER_DISCONNECT_THRESHOLD: i32 = 119;
const MINIMUM_MFA_PEER_DISCONNECT_THRESHOLD: i32 = 120;

#[sqlx::test]
async fn test_network(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, client_state) = make_test_client(pool).await;

    let mut gateway_rx = client_state.gateway_rx;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    let response = make_network(&client, "network").await;
    let network: WireguardNetwork<Id> = response.json().await;
    assert_eq!(network.name, "network");
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkCreated(..));

    // check vpn locations for `admin` group
    let admin_id = Group::find_by_name(&client_state.pool, "admin")
        .await
        .unwrap()
        .unwrap()
        .id;
    let response = client.get(format!("/api/v1/group/{admin_id}")).send().await;
    let group_info: GroupInfo = response.json().await;
    assert_eq!(group_info.vpn_locations, vec!["network"]);

    // modify network
    let network_data = WireguardNetworkData {
        name: "my network".into(),
        address: "10.1.1.1/24".into(),
        endpoint: "10.1.1.1".parse().unwrap(),
        port: 55555,
        allowed_ips: Some("10.1.1.0/24, 10.2.0.1/16, 10.10.10.54/32".into()),
        dns: None,
        mtu: DEFAULT_WIREGUARD_MTU,
        fwmark: 0,
        client_mtu: None,
        allow_all_groups: false,
        allowed_groups: vec!["admin".into()],
        keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        peer_disconnect_threshold: DEFAULT_DISCONNECT_THRESHOLD,
        acl_enabled: false,
        acl_default_allow: false,
        allowed_ips_from_acl: false,
        mfa_enabled: false,
        service_location_mode: ServiceLocationMode::Disabled,
        posture_checks: None,
        mfa_flows: Vec::new(),
        group_client_mtus: None,
    };
    let response = client
        .put(format!("/api/v1/network/{}", network.id))
        .json(&network_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let network: WireguardNetwork<Id> = response.json().await;
    assert_eq!(
        network.allowed_ips,
        vec![
            IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
            IpNetwork::V4("10.2.0.0/16".parse().unwrap()),
            IpNetwork::V4("10.10.10.54/32".parse().unwrap())
        ]
    );

    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkModified(..));

    // check vpn locations for `admin` group
    let response = client.get(format!("/api/v1/group/{admin_id}")).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let group_info: GroupInfo = response.json().await;
    assert_eq!(group_info.vpn_locations, vec!["my network"]);

    // list networks
    let response = client.get("/api/v1/network").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let networks: Vec<WireguardNetwork<Id>> = response.json().await;
    assert_eq!(networks.len(), 1);

    // network details
    let network_from_list = networks[0].clone();
    assert_eq!(network_from_list.name, "my network");
    let response = client
        .get(format!("/api/v1/network/{}", network_from_list.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let network_from_details: WireguardNetwork<Id> = response.json().await;
    assert_eq!(network_from_details, network_from_list);

    // delete network
    let response = client
        .delete(format!("/api/v1/network/{}", network.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkDeleted(..));
}

/// Build a location payload with overridable name, address and mode fields.
fn location_payload(
    name: &str,
    address: &str,
    mfa_enabled: bool,
    service_location_mode: &str,
) -> Value {
    json!({
        "name": name,
        "address": address,
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "allowed_groups": ["admin"],
        "allow_all_groups": false,
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": false,
        "acl_default_allow": false,
        "allowed_ips_from_acl": false,
        "mfa_enabled": mfa_enabled,
        "service_location_mode": service_location_mode,
        "posture_checks": [],
        "mfa_flows": []
    })
}

/// Create a minimal single-step MFA flow so that locations are allowed to enable MFA.
///
/// `PUT`/`POST /api/v1/network` refuses `mfa_enabled: true` with `no_flows_exist` while no flow
/// exists globally, so any test that enables MFA on a location has to create one first.
///
/// Returns the created flow's id so callers can assign it to a location.
async fn make_mfa_flow(client: &TestClient) -> i64 {
    let response = client
        .post("/api/v1/mfa-flow")
        .json(&json!({
            "title": "Test MFA Flow",
            "steps": [{ "methods": ["totp"] }]
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json::<Value>().await["id"].as_i64().unwrap()
}

/// Assign a flow as a location's default so the location can be MFA-enabled.
async fn assign_default_mfa_flow(client: &TestClient, location_id: i64, flow_id: i64) {
    let response = update_location_mfa_flows(
        client,
        location_id,
        json!([{ "flow_id": flow_id, "is_default": true, "group_ids": [] }]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Enabling MFA while no flow exists returns a structured `validation_failed` body that parses as
/// JSON in one step, not a JSON string wrapped inside `msg`.
#[sqlx::test]
async fn test_mfa_enabled_no_flows_structured_body(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let response = client
        .post("/api/v1/network")
        .json(&json!({
            "name": "no-flows",
            "address": "10.9.9.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.9.9.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": ["admin"],
            "allow_all_groups": false,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": true,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.json::<Value>().await;
    assert_eq!(body["error"], "validation_failed");
    assert_eq!(body["fields"][0]["field"], "mfa_flows");
    assert_eq!(body["fields"][0]["code"], "no_default_designated");
    assert!(
        body.get("msg").is_none(),
        "the refusal body must not be double-encoded via msg"
    );
}

/// Clearing assignments on an MFA-disabled location is allowed, and the location still cannot be
/// MFA-enabled afterward while no flows exist: the `no_flows_exist` precondition still guards the
/// toggle.
#[sqlx::test]
async fn test_enable_mfa_after_clear_refused_without_flows(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    // Create a flow and a location, assign, then clear.
    let flow_id = {
        let resp = client
            .post("/api/v1/mfa-flow")
            .json(&json!({"title": "Flow", "steps": [{"methods": ["totp"]}]}))
            .send()
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        resp.json::<Value>().await["id"].as_i64().unwrap()
    };

    let network_resp = make_network(&client, "clear-then-enable").await;
    let location_id = network_resp.json::<Value>().await["id"].as_i64().unwrap();

    let response = update_location_mfa_flows(
        &client,
        location_id,
        json!([
            {"flow_id": flow_id, "is_default": true, "group_ids": []},
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Clearing is allowed on the MFA-disabled location.
    let response = update_location_mfa_flows(&client, location_id, json!([])).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Delete the now-unassigned flow so no flows exist globally.
    let response = client
        .delete(format!("/api/v1/mfa-flow/{flow_id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Re-enabling MFA is still refused: no flows exist to assign.
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&json!({
            "name": "clear-then-enable",
            "address": "10.1.1.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.1.1.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": ["admin"],
            "allow_all_groups": false,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": true,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.json::<Value>().await;
    assert_eq!(body["fields"][0]["code"], "no_flows_exist");
}

/// Enabling MFA on a location that has no default flow assigned is refused with
/// `no_flows_assigned`, even when a flow exists globally.
#[sqlx::test]
async fn test_enable_mfa_without_assignment_refused(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    make_mfa_flow(&client).await;
    let network_resp = make_network(&client, "no-assignment").await;
    let location_id = network_resp.json::<Value>().await["id"].as_i64().unwrap();

    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&json!({
            "name": "no-assignment",
            "address": "10.1.1.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.1.1.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": ["admin"],
            "allow_all_groups": false,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": true,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.json::<Value>().await;
    assert_eq!(body["error"], "validation_failed");
    assert_eq!(body["fields"][0]["field"], "mfa_enabled");
    assert_eq!(body["fields"][0]["code"], "no_flows_assigned");
}

#[sqlx::test]
async fn test_modify_network_does_not_notify_gateway_when_commit_fails(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let response = client
        .post("/api/v1/network")
        .json(&location_payload(
            "location",
            "10.1.1.1/24",
            false,
            "disabled",
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let location: WireguardNetwork<Id> = response.json().await;

    let pool = client_state.pool.clone();
    let mut gateway_rx = client_state.gateway_rx;
    assert_matches!(
        gateway_rx.try_recv().unwrap(),
        GatewayCommand::NetworkCreated(..)
    );

    sqlx::query(
        "CREATE FUNCTION fail_network_update_commit() RETURNS trigger AS $$
         BEGIN
             RAISE EXCEPTION 'forced commit failure';
         END;
         $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER fail_network_update_commit
         AFTER UPDATE ON wireguard_network
         DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW EXECUTE FUNCTION fail_network_update_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();

    let response = client
        .put(format!("/api/v1/network/{}", location.id))
        .json(&location_payload(
            "renamed-location",
            "10.1.1.1/24",
            false,
            "disabled",
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_matches!(gateway_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));

    let response = client
        .get(format!("/api/v1/network/{}", location.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let persisted: WireguardNetwork<Id> = response.json().await;
    assert_eq!(persisted.name, "location");
}

#[sqlx::test]
async fn test_create_network_rejects_service_location_with_mfa(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    set_enterprise_license();

    for service_location_mode in ["prelogon", "alwayson"] {
        let response = client
            .post("/api/v1/network")
            .json(&location_payload(
                "mfa-service-location",
                "10.1.1.1/24",
                true,
                service_location_mode,
            ))
            .send()
            .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "MFA + service location mode {service_location_mode} must be rejected"
        );
    }

    // A plain location (no service location mode, no MFA) is fine
    let response = client
        .post("/api/v1/network")
        .json(&location_payload("plain", "10.1.1.1/24", false, "disabled"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

/// A zero keepalive stops `last_handshake` from ever advancing on an idle tunnel, which would make
/// the posture health check re-authorize forever (D6/R7). The web forms block it, but an API caller
/// bypasses them entirely, so core has to reject it too.
#[sqlx::test]
async fn test_network_rejects_zero_keepalive_interval(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    set_enterprise_license();

    let mut payload = location_payload("zero-keepalive", "10.1.1.1/24", false, "disabled");
    payload["keepalive_interval"] = json!(0);
    let response = client.post("/api/v1/network").json(&payload).send().await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "keepalive_interval 0 must be rejected on create"
    );

    // A valid location, so the same rule can be checked on the modify path.
    let response = client
        .post("/api/v1/network")
        .json(&location_payload(
            "good-keepalive",
            "10.2.2.1/24",
            false,
            "disabled",
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response.json::<Value>().await;
    let location_id = created["id"].as_i64().unwrap();

    let mut payload = location_payload("good-keepalive", "10.2.2.1/24", false, "disabled");
    payload["keepalive_interval"] = json!(0);
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&payload)
        .send()
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "keepalive_interval 0 must be rejected on modify"
    );

    // 1 is the floor, not a rejected edge.
    payload["keepalive_interval"] = json!(1);
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn test_peer_disconnect_threshold_validation_create(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;

    let (mut client, _client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    make_mfa_flow(&client).await;

    let mut location_data = WireguardNetworkData {
        name: "test_location_disabled".into(),
        address: "10.1.1.1/24".into(),
        endpoint: "10.1.1.1".parse().unwrap(),
        port: 55555,
        allowed_ips: Some("10.1.1.0/24, 10.2.0.1/16, 10.10.10.54/32".into()),
        dns: None,
        mtu: DEFAULT_WIREGUARD_MTU,
        fwmark: 0,
        client_mtu: None,
        allow_all_groups: false,
        allowed_groups: vec!["admin".into()],
        keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        peer_disconnect_threshold: INVALID_MFA_PEER_DISCONNECT_THRESHOLD,
        acl_enabled: false,
        acl_default_allow: false,
        allowed_ips_from_acl: false,
        mfa_enabled: false,
        service_location_mode: ServiceLocationMode::Disabled,
        posture_checks: None,
        mfa_flows: Vec::new(),
        group_client_mtus: None,
    };

    let response = client
        .post("/api/v1/network")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    location_data.name = "test_location_internal".into();
    location_data.mfa_enabled = true;
    let response = client
        .post("/api/v1/network")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Even with a valid threshold, creating a location already MFA-enabled is refused: a new
    // location has no default flow assigned yet, so enabling at create is always rejected.
    location_data.name = "test_location_internal_boundary".into();
    location_data.peer_disconnect_threshold = MINIMUM_MFA_PEER_DISCONNECT_THRESHOLD;
    let response = client
        .post("/api/v1/network")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.json::<Value>().await;
    assert_eq!(body["fields"][0]["code"], "no_default_designated");
}

#[sqlx::test]
async fn test_peer_disconnect_threshold_validation_modify(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;

    let (mut client, _client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    let flow_id = make_mfa_flow(&client).await;

    let mut location_data = WireguardNetworkData {
        name: "test_location".into(),
        address: "10.1.1.1/24".into(),
        endpoint: "10.1.1.1".parse().unwrap(),
        port: 55555,
        allowed_ips: Some("10.1.1.0/24, 10.2.0.1/16, 10.10.10.54/32".into()),
        dns: None,
        mtu: DEFAULT_WIREGUARD_MTU,
        fwmark: 0,
        client_mtu: None,
        allow_all_groups: false,
        allowed_groups: vec!["admin".into()],
        keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        peer_disconnect_threshold: INVALID_MFA_PEER_DISCONNECT_THRESHOLD,
        acl_enabled: false,
        acl_default_allow: false,
        allowed_ips_from_acl: false,
        mfa_enabled: false,
        service_location_mode: ServiceLocationMode::Disabled,
        posture_checks: None,
        mfa_flows: Vec::new(),
        group_client_mtus: None,
    };

    let response = client
        .post("/api/v1/network")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Give the location a default flow so the threshold checks below operate on a
    // MFA-enableable location.
    assign_default_mfa_flow(&client, 1, flow_id).await;
    location_data.mfa_flows = vec![
        xguard_common::db::models::mfa_flow::LocationMfaFlowAssignment {
            flow_id,
            is_default: true,
            group_ids: Vec::new(),
        },
    ];

    let response = client
        .put("/api/v1/network/1")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    location_data.mfa_enabled = true;
    let response = client
        .put("/api/v1/network/1")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    location_data.peer_disconnect_threshold = MINIMUM_MFA_PEER_DISCONNECT_THRESHOLD;
    let response = client
        .put("/api/v1/network/1")
        .json(&location_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn test_device(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, client_state) = make_test_client(pool).await;

    let mut gateway_rx = client_state.gateway_rx;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    make_network(&client, "network").await;
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkCreated(..));

    // network details
    let response = client.get("/api/v1/network/1").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let network_from_details: WireguardNetwork<Id> = response.json().await;

    // create device
    let device = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::DeviceCreated(..));

    // an IP was assigned for new device
    let network_devices = WireguardNetworkDevice::find_by_device(&client_state.pool, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        network_devices[0].wireguard_network_id,
        network_from_details.id
    );

    // add another network
    make_network(&client, "network").await;
    assert_matches!(
        gateway_rx.try_recv().unwrap(),
        GatewayCommand::NetworkCreated(..)
    );

    // an IP was assigned for an existing device
    let network_devices = WireguardNetworkDevice::find_by_device(&client_state.pool, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(network_devices.len(), 2);

    // list devices
    let response = client.get("/api/v1/device").json(&device).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(devices.len(), 1);
    let device = devices[0].clone();
    assert_eq!(device.name, "device");
    assert_eq!(
        device.wireguard_pubkey,
        "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU="
    );

    // list user devices
    let response = client
        .get("/api/v1/device/user/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let user_devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(user_devices.len(), 1);
    assert_eq!(devices.len(), 1);
    assert_eq!(device.id, user_devices[0].id);

    // modify device
    let modified_name = "modified-device";
    let modified_key = "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=";
    let mut modified_device = device.clone();
    modified_device.name = modified_name.into();
    modified_device.wireguard_pubkey = modified_key.into();
    let response = client
        .put(format!("/api/v1/device/{}", device.id))
        .json(&modified_device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::DeviceModified(..));

    // device details
    let response = client
        .get(format!("/api/v1/device/{}", device.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let device_from_details: Device<Id> = response.json().await;
    assert_eq!(device_from_details.name, modified_name);
    assert_eq!(device_from_details.wireguard_pubkey, modified_key);

    // device config
    let response = client
        .get(format!("/api/v1/network/1/device/{}/config", device.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let config = response.text().await;
    assert_eq!(
        config,
        format!(
            "[Interface]\n\
            PrivateKey = YOUR_PRIVATE_KEY\n\
            Address = 10.1.1.2\n\
            DNS = 1.1.1.1\n\
            \n\
            [Peer]\n\
            PublicKey = {}\n\
            AllowedIPs = 10.1.1.0/24\n\
            Endpoint = 192.168.4.14:55555\n\
            PersistentKeepalive = 25",
            network_from_details.pubkey
        )
    );

    let response = client
        .delete(format!("/api/v1/network/{}", network_from_details.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkDeleted(..));

    // delete device
    let response = client
        .delete(format!("/api/v1/device/{}", device.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::DeviceDeleted(..));

    let response = client.get("/api/v1/device").json(&device).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(devices, [] as [Device<Id>; 0]);
}

#[sqlx::test]
async fn test_network_address_reassignment(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, client_state) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    let response = make_network(&client, "network").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // network details
    let response = client.get("/api/v1/network/1").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let network_details = response.json::<Value>().await;
    let network_id = network_details["id"].as_i64().unwrap();

    // create devices
    let device = json!({
        "name": "device1",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device1 = response.json::<Value>().await;
    let device1_id = device1["device"]["id"].as_i64().unwrap();
    let device = json!({
        "name": "device2",
        "wireguard_pubkey": "ZqDlG4LQZRO9v57Sd27AHdtTLxegbMp5oVThjYrg21I=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device2 = response.json::<Value>().await;
    let device2_id = device2["device"]["id"].as_i64().unwrap();

    // ensure IPs were assigned for new devices
    let network_devices = WireguardNetworkDevice::find_by_device(&client_state.pool, device1_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        network_devices[0].wireguard_ips,
        vec![IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2))],
    );
    let network_devices = WireguardNetworkDevice::find_by_device(&client_state.pool, device2_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        network_devices[0].wireguard_ips,
        vec![IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3))],
    );

    // trying to modify network addresses while devices exist shouldn't fail
    let network = json!({
        "id": network_id,
        "name": "network",
        "address": "10.1.1.1/24,fc00::1/112",
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "allow_all_groups": false,
        "allowed_groups": ["admin"],
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": false,
        "acl_default_allow": false,
            "allowed_ips_from_acl": false,
        "mfa_enabled": false,
        "service_location_mode": "disabled",
        "posture_checks": [],
        "mfa_flows": []
    });
    let response = client
        .put(format!("/api/v1/network/{network_id}"))
        .json(&network)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // delete both devices
    let response = client
        .delete(format!("/api/v1/device/{device1_id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .delete(format!("/api/v1/device/{device2_id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // re-create a device and verify it gets IPs in both subnets
    let device = json!({
        "name": "device3",
        "wireguard_pubkey": "o/8q3kmv5nnbrcb/7aceQWGE44a0yI707wObXRyyWGU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device3 = response.json::<Value>().await;
    let device3_id = device3["device"]["id"].as_i64().unwrap();

    let network_devices = WireguardNetworkDevice::find_by_device(&client_state.pool, device3_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        network_devices[0].wireguard_ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 2)),
        ],
    );
}

#[sqlx::test]
async fn test_device_permissions(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, _) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    make_network(&client, "network").await;

    // admin can add devices for other users
    let device = json!({
        "name": "device_1",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = json!({"devices": [{
        "name": "device_2",
        "wireguard_ips": ["10.0.0.3"],
        "wireguard_pubkey": "TJgN9JzUF5zdZAPYD96G/Wys2M3TvaT5TIrErUl20nI=",
        "user_id": 1,
        "created": "2023-05-05T23:56:04"
    }]});
    let response = client
        .post("/api/v1/network/1/devices")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let device = json!({
        "name": "device_3",
        "wireguard_pubkey": "PKY3zg5/ecNyMjqLi6yJ3jwb4PvC/SGzjhJ3jrn2vVQ=",
    });
    let response = client
        .post("/api/v1/device/hpotter")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = json!({"devices": [{
        "name": "device_4",
        "wireguard_ips": ["10.0.0.5"],
        "wireguard_pubkey": "gTMFF29nNLkJR1UhoiO3ZJLF60h2hW+WxmIu5DGJ0B4=",
        "user_id": 2,
        "created": "2023-05-05T23:56:04"
    }]});
    let response = client
        .post("/api/v1/network/1/devices")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // normal user cannot add devices for other users or import multiple devices
    let auth = Auth::new("hpotter", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let device = json!({
        "name": "device_5",
        "wireguard_pubkey": "qhLnyggsD1nVOcLdTk0q43kOZHHknPQgftBY+ZLy40Q=",
    });
    let response = client
        .post("/api/v1/device/hpotter")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = json!({"devices": [{
        "name": "device_6",
        "wireguard_ips": ["10.0.0.7"],
        "wireguard_pubkey": "xGLqgxVAnmk9+tsj5X/wzwouwx3bF1b3W+VWAb4NLjM=",
        "user_id": 2,
        "created": "2023-05-05T23:56:04"
    }]});
    let response = client
        .post("/api/v1/network/1/devices")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let device = json!({
        "name": "device_7",
        "wireguard_pubkey": "J4p/w6R0xt4c2dIBDJ73BmzGJeF0QLW/iihPnISJMkg=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let device = json!({"devices": [{
        "name": "device_8",
        "wireguard_ips": ["10.0.0.9"],
        "wireguard_pubkey": "A2cg4qMe+s0MSFlV6xyhz7XY6PrET6mli9GVSUshXAk=",
        "user_id": 1,
        "created": "2023-05-05T23:56:04"
    }]});
    let response = client
        .post("/api/v1/network/1/devices")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // normal user cannot list devices of other users
    let response = client.get("/api/v1/device/user/admin").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = client.get("/api/v1/device/user/hpotter").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let user_devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(user_devices.len(), 3);

    // admin can list devices of other users
    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = client.get("/api/v1/device/user/admin").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let user_devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(user_devices.len(), 2);

    let response = client.get("/api/v1/device/user/hpotter").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let user_devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(user_devices.len(), 3);
}

#[sqlx::test]
async fn test_device_pubkey(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, client_state) = make_test_client(pool).await;

    let mut gateway_rx = client_state.gateway_rx;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    make_network(&client, "network").await;
    let event = gateway_rx.try_recv().unwrap();
    assert_matches!(event, GatewayCommand::NetworkCreated(..));

    // network details
    let response = client.get("/api/v1/network/1").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let network_from_details: WireguardNetwork<Id> = response.json().await;

    // create bad device
    let device = json!({
        "name": "device",
        "wireguard_pubkey": network_from_details.pubkey.clone(),
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // create another bad device
    let device = json!({
        "name": "device",
        "wireguard_pubkey": "invalid_key",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // create good device
    let device = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // list devices
    let response = client.get("/api/v1/device").json(&device).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(devices.len(), 1);

    // modify device
    let mut device = devices[0].clone();
    device.wireguard_pubkey = network_from_details.pubkey;
    let response = client
        .put(format!("/api/v1/device/{}", device.id))
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // try to create multiple devices
    let devices = json!({"devices": [{
        "name": "device_2",
        "wireguard_ips": ["10.0.0.9"],
        "wireguard_pubkey": "o/8q3kmv5nnbrcb/7aceQWGE44a0yI707wObXRyyWGU=",
        "user_id": 1,
        "created": "2023-05-05T23:56:04"
    },
    {
        "name": "device_3",
        "wireguard_ips": ["10.0.0.10"],
        "wireguard_pubkey": "invalid_key",
        "user_id": 1,
        "created": "2023-05-05T23:56:04"
    }]});
    let response = client
        .post("/api/v1/network/1/devices")
        .json(&devices)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // make sure no device was created
    let response = client.get("/api/v1/device").json(&device).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let devices: Vec<Device<Id>> = response.json().await;
    assert_eq!(devices.len(), 1);
}

#[sqlx::test]
async fn test_network_size_validation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;

    let (client, _client_state) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = &client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // create network
    let response = make_network(&client, "network").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // network details
    let response = client.get("/api/v1/network/1").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let network_from_details: WireguardNetwork<Id> = response.json().await;

    // try to add subnet with invalid mask (/0)
    let network = json!({
        "id": network_from_details.id,
        "name": "network",
        "address": "10.2.0.1/24,10.1.1.1/0",
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "allow_all_groups": false,
        "allowed_groups": ["admin"],
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": false,
        "acl_default_allow": false,
            "allowed_ips_from_acl": false,
        "mfa_enabled": false,
        "service_location_mode": "disabled",
        "posture_checks": [],
        "mfa_flows": []
    });
    let response = client
        .put(format!("/api/v1/network/{}", network_from_details.id))
        .json(&network)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // try to add no network (empty address)
    let network = json!({
        "id": network_from_details.id,
        "name": "network",
        "address": "",
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "allow_all_groups": false,
        "allowed_groups": ["admin"],
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": false,
        "acl_default_allow": false,
            "allowed_ips_from_acl": false,
        "mfa_enabled": false,
        "service_location_mode": "disabled",
        "posture_checks": [],
        "mfa_flows": []
    });
    let response = client
        .put(format!("/api/v1/network/{}", network_from_details.id))
        .json(&network)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[derive(serde::Deserialize)]
struct DeviceWireGuardConfig {
    network_id: Id,
    network_name: String,
    config: String,
}

/// A user allowed in a single location returns exactly one device config.
#[sqlx::test]
async fn test_user_device_configs_single_network(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let network: WireguardNetwork<Id> = make_network(&client, "network").await.json().await;

    let device_payload = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = response.json::<Value>().await;
    let device_id = device["device"]["id"].as_i64().unwrap();

    let response = client
        .get(format!("/api/v1/device/{device_id}/config"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let configs: Vec<DeviceWireGuardConfig> = response.json().await;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].network_id, network.id);
    assert_eq!(configs[0].network_name, network.name);
    assert!(configs[0].config.contains("[Interface]"));
    assert!(configs[0].config.contains("[Peer]"));
}

/// A user allowed in multiple networks returns a device config entry for each location.
#[sqlx::test]
async fn test_user_device_configs_multiple_networks(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let location1: WireguardNetwork<Id> = make_network(&client, "location-1").await.json().await;
    let location2: WireguardNetwork<Id> = make_network(&client, "location-2").await.json().await;

    // Both locations use allow_all_groups=true (make_network default), so the device
    // will be allowed in both when created.
    let device_payload = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = response.json::<Value>().await;
    let device_id = device["device"]["id"].as_i64().unwrap();

    let response = client
        .get(format!("/api/v1/device/{device_id}/config"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let configs: Vec<DeviceWireGuardConfig> = response.json().await;

    assert_eq!(configs.len(), 2, "expected configs for both locations");
    let ids: Vec<Id> = configs.iter().map(|c| c.network_id).collect();
    assert!(ids.contains(&location1.id), "config for location-1 missing");
    assert!(ids.contains(&location2.id), "config for location-2 missing");
    for cfg in &configs {
        assert!(cfg.config.contains("[Interface]"));
        assert!(cfg.config.contains("[Peer]"));
    }
}

/// A non-admin user can fetch configs for their own device but not for another user's device.
#[sqlx::test]
async fn test_user_device_configs_auth(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // Create a location that allows all users (not just admin group)
    client
        .post("/api/v1/network")
        .json(&json!({
            "name": "network",
            "address": "10.1.1.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.1.1.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": [],
            "allow_all_groups": true,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": false,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await;

    // Create a device for hpotter (non-admin user)
    let device_payload = json!({
        "name": "hpotter-device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/hpotter")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let hpotter_device = response.json::<Value>().await;
    let hpotter_device_id = hpotter_device["device"]["id"].as_i64().unwrap();

    // Create a device for admin
    let device_payload = json!({
        "name": "admin-device",
        "wireguard_pubkey": "sIhx53MsX+iLk83sssybHrD7M+5m+CmpLzWL/zo8C38=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let admin_device = response.json::<Value>().await;
    let admin_device_id = admin_device["device"]["id"].as_i64().unwrap();

    // Switch to hpotter
    let auth = Auth::new("hpotter", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    // hpotter can fetch their own device config
    let response = client
        .get(format!("/api/v1/device/{hpotter_device_id}/config"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let configs: Vec<DeviceWireGuardConfig> = response.json().await;
    assert_eq!(configs.len(), 1);

    // hpotter cannot fetch admin's device config
    let response = client
        .get(format!("/api/v1/device/{admin_device_id}/config"))
        .send()
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "non-admin user should not access another user's device config"
    );
}

/// Regression test: an admin manually adding a device for a disabled user used to
/// silently succeed with an empty config list, since the device was never actually
/// allowed to join any network. Disabled users' devices are also stripped from every
/// network on the next sync anyway (see `process_device_access_changes`), so letting
/// an admin add one would only work until that sync runs.
#[sqlx::test]
async fn test_add_device_for_disabled_user(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    // Network open to all users, so the only thing blocking the device is `is_active`.
    client
        .post("/api/v1/network")
        .json(&json!({
            "name": "network",
            "address": "10.1.1.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.1.1.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": [],
            "allow_all_groups": true,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": false,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await;

    // Disable hpotter.
    let mut user_details = fetch_user_details(&client, "hpotter").await;
    user_details.user.is_active = false;
    let response = client
        .put("/api/v1/user/hpotter")
        .json(&user_details.user)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Admin tries to add a device for the disabled user manually. Should be rejected
    // outright, not silently created with no usable config.
    let device_payload = json!({
        "name": "disabled-user-device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/hpotter")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// MFA locations (internal/external) must be excluded from the user device config endpoint.
/// A user should only receive configs for regular (non-MFA) locations since MFA location
/// connections are possible only with the XGuard client apps, not standard WireGuard clients.
#[sqlx::test]
async fn test_user_device_configs_excludes_mfa_locations(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (client, _) = make_test_client(pool).await;

    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let flow_id = make_mfa_flow(&client).await;

    // Create a normal location (allow_all_groups so the device is allowed)
    let normal_location: WireguardNetwork<Id> = client
        .post("/api/v1/network")
        .json(&json!({
            "name": "normal-location",
            "address": "10.1.1.1/24",
            "port": 55555,
            "endpoint": "192.168.4.14",
            "allowed_ips": "10.1.1.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": [],
            "allow_all_groups": true,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": false,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await
        .json()
        .await;

    // Create an MFA location (internal mode, no enterprise license required). It starts with MFA
    // off: a new location cannot be created already enabled, so we assign a flow and enable it.
    let mfa_location: WireguardNetwork<Id> = client
        .post("/api/v1/network")
        .json(&json!({
            "name": "mfa-location",
            "address": "10.1.2.1/24",
            "port": 55556,
            "endpoint": "192.168.4.15",
            "allowed_ips": "10.1.2.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": [],
            "allow_all_groups": true,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": false,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": []
        }))
        .send()
        .await
        .json()
        .await;

    assign_default_mfa_flow(&client, mfa_location.id, flow_id).await;

    let response = client
        .put(format!("/api/v1/network/{}", mfa_location.id))
        .json(&json!({
            "name": "mfa-location",
            "address": "10.1.2.1/24",
            "port": 55556,
            "endpoint": "192.168.4.15",
            "allowed_ips": "10.1.2.0/24",
            "dns": "1.1.1.1",
            "mtu": 1420,
            "fwmark": 0,
            "allowed_groups": [],
            "allow_all_groups": true,
            "keepalive_interval": 25,
            "peer_disconnect_threshold": 300,
            "acl_enabled": false,
            "acl_default_allow": false,
            "allowed_ips_from_acl": false,
            "mfa_enabled": true,
            "service_location_mode": "disabled",
            "posture_checks": [],
            "mfa_flows": [{"flow_id": flow_id, "is_default": true, "group_ids": []}]
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Create a user device
    let device_payload = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device_payload)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device = response.json::<Value>().await;
    let device_id = device["device"]["id"].as_i64().unwrap();

    let response = client
        .get(format!("/api/v1/device/{device_id}/config"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let configs: Vec<DeviceWireGuardConfig> = response.json().await;

    // Only the normal location config should be returned
    assert_eq!(configs.len(), 1, "MFA location should be excluded");
    assert_eq!(
        configs[0].network_id, normal_location.id,
        "config should belong to the normal location"
    );
    assert_ne!(
        configs[0].network_id, mfa_location.id,
        "MFA location config must not be returned"
    );
}

/// Set a cached enterprise-tier license for tests that need ACL AllowedIPs.
/// No-op: XGuard has no license tiers.
fn set_enterprise_license() {}

#[sqlx::test]
async fn test_static_ip_assignment_sends_device_modified(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (client, client_state) = make_test_client(pool).await;
    let mut gateway_rx = client_state.gateway_rx;

    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);

    make_network(&client, "network").await;
    assert_matches!(
        gateway_rx.try_recv().unwrap(),
        GatewayCommand::NetworkCreated(..)
    );

    let device = json!({
        "name": "device",
        "wireguard_pubkey": "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=",
    });
    let response = client
        .post("/api/v1/device/admin")
        .json(&device)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let GatewayCommand::DeviceCreated(created) = gateway_rx.try_recv().unwrap() else {
        panic!("expected DeviceCreated");
    };
    let device_id = created.device.id;
    let network_id = created.network_info[0].network_id;

    let new_ip: IpAddr = "10.1.1.42".parse().unwrap();
    let response = client
        .post("/api/v1/device/user/admin/ip")
        .json(&json!([{
            "device_id": device_id,
            "location_id": network_id,
            "ips": [new_ip],
        }]))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let GatewayCommand::DeviceModified(modified) = gateway_rx.try_recv().unwrap() else {
        panic!("expected DeviceModified after static IP assignment");
    };
    assert_eq!(modified.device.id, device_id);
    assert_eq!(modified.network_info.len(), 1);
    assert_eq!(modified.network_info[0].network_id, network_id);
    assert_eq!(modified.network_info[0].device_wireguard_ips, vec![new_ip]);

    // ACLs are disabled for this location, so no firewall update follows.
    assert!(gateway_rx.try_recv().is_err());
}

fn location_json_with_group_client_mtus(name: &str, group_client_mtus: Value) -> Value {
    json!({
        "name": name,
        "address": "10.1.1.1/24",
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "allowed_groups": [],
        "allow_all_groups": true,
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": false,
        "acl_default_allow": false,
        "allowed_ips_from_acl": false,
        "mfa_enabled": false,
        "service_location_mode": "disabled",
        "posture_checks": [],
        "mfa_flows": [],
        "group_client_mtus": group_client_mtus,
    })
}

#[sqlx::test]
async fn test_service_locations_are_not_supported(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    for service_location_mode in ["prelogon", "alwayson"] {
        let response = client
            .post("/api/v1/network")
            .json(&location_payload(
                "service-location",
                "10.1.1.1/24",
                false,
                service_location_mode,
            ))
            .send()
            .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "service location mode {service_location_mode} must be rejected"
        );
    }
}

#[sqlx::test]
async fn test_group_client_mtu_overrides_are_not_supported(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, client_state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let group = Group::new("mtu_group")
        .save(&client_state.pool)
        .await
        .unwrap()
        .id;
    let create_data = location_json_with_group_client_mtus(
        "network",
        json!([{"client_mtu": 1300, "group_ids": [group]}]),
    );
    let response = client
        .post("/api/v1/network")
        .json(&create_data)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
