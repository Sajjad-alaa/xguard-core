//! "Allowed IPs from firewall rules": the location option over the API, its audit event, and the
//! AllowedIPs in the configurations the web UI downloads (config file, QR code, device configs).

use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_core::events::ApiEventType;

use super::common::{
    authenticate_admin, client::TestClient, get_db_user, make_test_client, setup_pool,
};

const USER_PUBKEY: &str = "AJwxGkzvVVn5Q1xjpCDFo5RJSU9KOPHeoEixYaj+20M=";

fn location(allowed_ips_from_acl: bool) -> Value {
    json!({
        "name": "office",
        "address": "10.1.1.1/24",
        "port": 55555,
        "endpoint": "vpn.example.com",
        "allowed_ips": "0.0.0.0/0",
        "dns": "10.1.1.53, corp.example.com",
        "mtu": 1420,
        "fwmark": 0,
        "allow_all_groups": true,
        "allowed_groups": [],
        "keepalive_interval": 25,
        "peer_disconnect_threshold": 300,
        "acl_enabled": true,
        "acl_default_allow": false,
        "allowed_ips_from_acl": allowed_ips_from_acl,
        "mfa_enabled": false,
        "service_location_mode": "disabled",
        "posture_checks": [],
        "mfa_flows": [],
    })
}

async fn set_option(client: &mut TestClient, id: i64, on: bool) -> Vec<ApiEventType> {
    client.drain_all_events();
    let response = client
        .put(format!("/api/v1/network/{id}"))
        .json(&location(on))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await;
    assert_eq!(body["allowed_ips_from_acl"], json!(on));
    client
        .drain_all_events()
        .into_iter()
        .map(|(event, _, _)| event)
        .collect()
}

/// The `AllowedIPs` line of the downloadable configuration, and the `allowed_ips` of the device
/// configs the web UI shows (QR code and copy).
async fn routes(client: &TestClient, location_id: i64, device_id: i64) -> (String, Value) {
    let response = client
        .get(format!(
            "/api/v1/network/{location_id}/device/{device_id}/config"
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let config = response.text().await;
    let line = config
        .lines()
        .find_map(|line| line.strip_prefix("AllowedIPs = "))
        .unwrap_or_default()
        .to_string();

    let response = client
        .get(format!("/api/v1/device/{device_id}/config"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let configs: Value = response.json().await;
    let config = configs
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["network_id"] == json!(location_id))
        .expect("config for the location")["config"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        config.contains(&format!("AllowedIPs = {line}\n")),
        "both endpoints agree: {config}"
    );
    (line, configs)
}

#[sqlx::test]
async fn test_allowed_ips_from_firewall_rules(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;
    let hpotter = get_db_user(&pool, "hpotter").await;

    let response = client
        .post("/api/v1/network")
        .json(&location(false))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let location_id = response.json::<Value>().await["id"].as_i64().unwrap();

    let response = client
        .post("/api/v1/device/hpotter")
        .json(&json!({"name": "laptop", "wireguard_pubkey": USER_PUBKEY}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let device_id = response.json::<Value>().await["device"]["id"]
        .as_i64()
        .unwrap();

    for rule in [
        json!({
            "name": "hpotter intranet",
            "action": "allow",
            "all_locations": true,
            "users": [hpotter.id],
            "destinations": ["192.168.10.0/24", "192.168.11.0/24"],
            "protocols": [6],
            "ports": ["443"],
        }),
        json!({
            "name": "deny lan",
            "action": "deny",
            "priority": 1,
            "all_locations": true,
            "all_users": true,
            "destinations": ["172.16.0.0/12"],
        }),
    ] {
        let response = client
            .post("/api/v1/firewall/rule")
            .json(&rule)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // Off: the static list, exactly as before.
    assert_eq!(routes(&client, location_id, device_id).await.0, "0.0.0.0/0");

    // On: the VPN network, the DNS server inside it and what the rules allow, merged.
    let events = set_option(&mut client, location_id, true).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            ApiEventType::LocationAclAllowedIpsChanged { location_id: id, enabled: true, .. }
                if *id == location_id
        )),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, ApiEventType::VpnLocationModified { .. }))
    );
    let (line, configs) = routes(&client, location_id, device_id).await;
    assert_eq!(line, "10.1.1.0/24,192.168.10.0/23");
    assert!(configs.is_array());

    // A rule change shows in the next configuration.
    let response = client
        .post("/api/v1/firewall/rule")
        .json(&json!({
            "name": "everyone wiki",
            "action": "allow",
            "all_locations": true,
            "any_source": true,
            "destinations": ["10.20.0.5"],
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        routes(&client, location_id, device_id).await.0,
        "10.1.1.0/24,10.20.0.5/32,192.168.10.0/23"
    );

    // Saving without changing the option logs no option change.
    let events = set_option(&mut client, location_id, true).await;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, ApiEventType::LocationAclAllowedIpsChanged { .. })),
        "{events:?}"
    );

    // Off again: logged, and the static list is back.
    let events = set_option(&mut client, location_id, false).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            ApiEventType::LocationAclAllowedIpsChanged { enabled: false, .. }
        )),
        "{events:?}"
    );
    assert_eq!(routes(&client, location_id, device_id).await.0, "0.0.0.0/0");
}
