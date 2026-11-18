//! Client and device settings: the admin API, its validation and audit events, and the
//! server-side enforcement in the device API.

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::{sync::mpsc, time::timeout};
use xguard_common::{
    db::models::{ClientSettings, ClientTrafficPolicy, group::Group},
    types::proxy::ProxyControlMessage,
};
use xguard_core::events::ApiEventType;

use super::common::{authenticate_admin, client::TestClient, make_test_client, setup_pool};

const USER_PUBKEY: &str = "AJwxGkzvVVn5Q1xjpCDFo5RJSU9KOPHeoEixYaj+20M=";
const OTHER_PUBKEY: &str = "LQKsT6/3HWKuJmMulH63R8iK+5sI8FyYEL6WDIi6lQU=";

fn location(name: &str, group_client_mtus: Value) -> Value {
    json!({
        "name": name,
        "address": "10.1.1.1/24",
        "port": 55555,
        "endpoint": "192.168.4.14",
        "allowed_ips": "10.1.1.0/24",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "fwmark": 0,
        "client_mtu": 1400,
        "allow_all_groups": true,
        "allowed_groups": [],
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

async fn create_location(client: &mut TestClient) -> i64 {
    let response = client
        .post("/api/v1/network")
        .json(&location("network", json!([])))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = response.json::<Value>().await["id"].as_i64().unwrap();
    client.drain_all_events();
    id
}

async fn patch(client: &TestClient, body: Value) -> StatusCode {
    client
        .patch("/api/v1/client_settings")
        .json(&body)
        .send()
        .await
        .status()
}

async fn get_settings(client: &TestClient) -> Value {
    let response = client.get("/api/v1/client_settings").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await
}

/// Adds a device for `hpotter` as the current user; returns the status and the device ID.
async fn add_device(client: &TestClient, name: &str, pubkey: &str) -> (StatusCode, Option<i64>) {
    let response = client
        .post("/api/v1/device/hpotter")
        .json(&json!({"name": name, "wireguard_pubkey": pubkey}))
        .send()
        .await;
    let status = response.status();
    let id = if status == StatusCode::CREATED {
        response.json::<Value>().await["device"]["id"].as_i64()
    } else {
        None
    };
    (status, id)
}

#[sqlx::test]
async fn test_client_settings_defaults_and_access(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;

    let settings = get_settings(&client).await;
    assert_eq!(
        settings,
        json!({
            "admin_device_management": false,
            "only_client_activation": false,
            "client_traffic_policy": "none",
            "disable_tunnels": false,
            "display_download_step": true,
            "display_password_reset": true,
            "group_client_traffic_policies": {
                "none": [], "disable_all_traffic": [], "force_all_traffic": []
            }
        })
    );
    // The pre-XGuard path serves the same resource.
    let response = client.get("/api/v1/settings_enterprise").send().await;
    assert_eq!(response.json::<Value>().await, settings);

    let group = Group::new("restricted").save(&pool).await.unwrap();
    assert_eq!(
        patch(
            &client,
            json!({"group_client_traffic_policies": {
                "none": [], "disable_all_traffic": [group.id], "force_all_traffic": []
            }})
        )
        .await,
        StatusCode::OK
    );

    // Users can read the settings (the UI hides forbidden actions), but not the group overrides,
    // and cannot change anything.
    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let settings = get_settings(&client).await;
    assert_eq!(settings["admin_device_management"], json!(false));
    assert_eq!(
        settings["group_client_traffic_policies"]["disable_all_traffic"],
        json!([])
    );
    assert_eq!(
        patch(&client, json!({"admin_device_management": true})).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .patch("/api/v1/settings_enterprise")
            .json(&json!({"admin_device_management": true}))
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        !ClientSettings::load(&pool)
            .await
            .unwrap()
            .admin_device_management
    );
}

#[sqlx::test]
async fn test_client_settings_validation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;
    let group = Group::new("one").save(&pool).await.unwrap();
    let before = get_settings(&client).await;
    client.drain_all_events();

    // Unknown fields and values are rejected rather than ignored.
    assert!(
        patch(&client, json!({"admin_device_managment": true}))
            .await
            .is_client_error()
    );
    assert!(
        patch(&client, json!({"client_traffic_policy": "everything"}))
            .await
            .is_client_error()
    );
    assert!(
        patch(
            &client,
            json!({"group_client_traffic_policies": {"none": [], "disable_all_traffic": []}})
        )
        .await
        .is_client_error()
    );
    // A group can have one policy only, also within one list.
    for policies in [
        json!({"none": [group.id], "disable_all_traffic": [group.id], "force_all_traffic": []}),
        json!({"none": [], "disable_all_traffic": [], "force_all_traffic": [group.id, group.id]}),
    ] {
        assert_eq!(
            patch(
                &client,
                json!({"admin_device_management": true, "group_client_traffic_policies": policies})
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }
    // Unknown groups.
    assert_eq!(
        patch(
            &client,
            json!({"only_client_activation": true, "group_client_traffic_policies": {
                "none": [], "disable_all_traffic": [group.id, 9999], "force_all_traffic": []
            }})
        )
        .await,
        StatusCode::BAD_REQUEST
    );

    // Nothing was saved and nothing was logged.
    assert_eq!(get_settings(&client).await, before);
    assert!(client.drain_all_events().is_empty());
}

#[sqlx::test]
async fn test_client_settings_update_is_saved_and_audited(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;
    let first = Group::new("first").save(&pool).await.unwrap();
    let second = Group::new("second").save(&pool).await.unwrap();
    client.drain_all_events();

    let response = client
        .patch("/api/v1/client_settings")
        .json(&json!({
            "client_traffic_policy": "force_all_traffic",
            "disable_tunnels": true,
            "group_client_traffic_policies": {
                "none": [second.id], "disable_all_traffic": [first.id], "force_all_traffic": []
            }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: Value = response.json().await;
    assert_eq!(returned, get_settings(&client).await);
    assert_eq!(
        returned["client_traffic_policy"],
        json!("force_all_traffic")
    );
    assert_eq!(returned["disable_tunnels"], json!(true));
    // Untouched fields keep their value.
    assert_eq!(returned["display_download_step"], json!(true));
    assert_eq!(
        returned["group_client_traffic_policies"],
        json!({"none": [second.id], "disable_all_traffic": [first.id], "force_all_traffic": []})
    );

    let stored = ClientSettings::load(&pool).await.unwrap();
    assert_eq!(
        stored.client_traffic_policy,
        ClientTrafficPolicy::ForceAllTraffic
    );
    assert!(stored.disable_tunnels);

    let events = client.drain_all_events();
    let [(ApiEventType::ClientSettingsUpdated { before, after }, _, _)] = events.as_slice() else {
        panic!("expected one ClientSettingsUpdated event, got {events:?}");
    };
    assert_eq!(before.settings, ClientSettings::default());
    assert_eq!(after.settings, stored);
    assert_eq!(
        after.group_client_traffic_policies.disable_all_traffic,
        [first.id]
    );

    // Repeating the same change is not logged again.
    assert_eq!(
        patch(&client, json!({"disable_tunnels": true})).await,
        StatusCode::OK
    );
    assert!(client.drain_all_events().is_empty());

    // Deleting a group removes its override.
    first.delete(&pool).await.unwrap();
    assert_eq!(
        get_settings(&client).await["group_client_traffic_policies"]["disable_all_traffic"],
        json!([])
    );
}

#[sqlx::test]
async fn test_admin_device_management_is_enforced(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    create_location(&mut client).await;

    // While users manage their own devices, hpotter can add one.
    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let (status, own_device) = add_device(&client, "own", USER_PUBKEY).await;
    assert_eq!(status, StatusCode::CREATED);
    let own_device = own_device.unwrap();

    client.drain_all_events();
    authenticate_admin(&mut client).await;
    assert_eq!(
        patch(&client, json!({"admin_device_management": true})).await,
        StatusCode::OK
    );
    // Admins are not restricted.
    let (status, _) = add_device(&client, "by-admin", OTHER_PUBKEY).await;
    assert_eq!(status, StatusCode::CREATED);
    let response = client
        .post("/api/v1/user/hpotter/start_desktop")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let (status, _) = add_device(
        &client,
        "another",
        "FuwGQn43HeNGytYuAcDwMhS5wTHPnqqrldQvHNS/1YQ=",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let response = client
        .put(format!("/api/v1/device/{own_device}"))
        .json(&json!({"name": "renamed", "wireguard_pubkey": USER_PUBKEY}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = client
        .delete(format!("/api/v1/device/{own_device}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = client
        .post("/api/v1/user/hpotter/start_desktop")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Reading devices still works.
    let response = client
        .get(format!("/api/v1/device/{own_device}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn test_only_client_activation_is_enforced(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    let location_id = create_location(&mut client).await;

    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let (status, device) = add_device(&client, "own", USER_PUBKEY).await;
    assert_eq!(status, StatusCode::CREATED);
    let device = device.unwrap();
    let config_paths = [
        format!("/api/v1/network/{location_id}/device/{device}/config"),
        format!("/api/v1/device/{device}/config"),
    ];
    for path in &config_paths {
        assert_eq!(client.get(path).send().await.status(), StatusCode::OK);
    }

    client.drain_all_events();
    authenticate_admin(&mut client).await;
    assert_eq!(
        patch(&client, json!({"only_client_activation": true})).await,
        StatusCode::OK
    );
    // Admins can still download configs and add devices manually.
    for path in &config_paths {
        assert_eq!(client.get(path).send().await.status(), StatusCode::OK);
    }
    let (status, _) = add_device(&client, "by-admin", OTHER_PUBKEY).await;
    assert_eq!(status, StatusCode::CREATED);

    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let (status, _) = add_device(
        &client,
        "manual",
        "FuwGQn43HeNGytYuAcDwMhS5wTHPnqqrldQvHNS/1YQ=",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for path in &config_paths {
        assert_eq!(
            client.get(path).send().await.status(),
            StatusCode::FORBIDDEN
        );
    }
    // Renaming is allowed, replacing the key is not.
    let response = client
        .put(format!("/api/v1/device/{device}"))
        .json(&json!({"name": "renamed", "wireguard_pubkey": USER_PUBKEY}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .put(format!("/api/v1/device/{device}"))
        .json(&json!({"name": "renamed", "wireguard_pubkey": "FuwGQn43HeNGytYuAcDwMhS5wTHPnqqrldQvHNS/1YQ="}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Starting a desktop activation is how devices are added now.
    let response = client
        .post("/api/v1/user/hpotter/start_desktop")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn next_public_settings(rx: &mut mpsc::Receiver<ProxyControlMessage>) -> (bool, bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Some(ProxyControlMessage::BroadcastPublicSettings {
                    display_password_reset,
                    display_download_step,
                    ..
                }) => return (display_password_reset, display_download_step),
                Some(_) => {}
                None => panic!("proxy control channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for BroadcastPublicSettings")
}

#[sqlx::test]
async fn test_edge_display_flags_are_broadcast(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, state) = make_test_client(pool).await;
    let mut rx = state.proxy_control_rx;
    authenticate_admin(&mut client).await;
    while rx.try_recv().is_ok() {}

    assert_eq!(
        patch(&client, json!({"display_download_step": false})).await,
        StatusCode::OK
    );
    // Without SMTP, password reset stays hidden whatever the toggle says.
    assert_eq!(next_public_settings(&mut rx).await, (false, false));

    // Changes that do not affect Edge are not broadcast.
    assert_eq!(
        patch(&client, json!({"disable_tunnels": true})).await,
        StatusCode::OK
    );
    assert!(rx.try_recv().is_err());

    // With SMTP configured, the toggle decides.
    let response = client
        .patch("/api/v1/settings")
        .json(&json!({
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_sender": "noreply@example.com",
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(next_public_settings(&mut rx).await, (true, false));
    assert_eq!(
        patch(&client, json!({"display_password_reset": false})).await,
        StatusCode::OK
    );
    assert_eq!(next_public_settings(&mut rx).await, (false, false));
}

#[sqlx::test]
async fn test_group_client_mtus_are_saved_and_audited(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;
    let small = Group::new("small-mtu").save(&pool).await.unwrap();
    let smaller = Group::new("smaller-mtu").save(&pool).await.unwrap();
    client.drain_all_events();

    let response = client
        .post("/api/v1/network")
        .json(&location(
            "network",
            json!([{"client_mtu": 1300, "group_ids": [small.id]}]),
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = response.json::<Value>().await["id"].as_i64().unwrap();
    let events = client.drain_all_events();
    assert!(
        events.iter().any(|(event, _, _)| matches!(
            event,
            ApiEventType::LocationGroupMtusChanged { before, after, .. }
                if before.is_empty() && after.len() == 1
        )),
        "{events:?}"
    );

    let details: Value = client
        .get(format!("/api/v1/network/{id}"))
        .send()
        .await
        .json()
        .await;
    assert_eq!(
        details["group_client_mtus"],
        json!([{"client_mtu": 1300, "group_ids": [small.id]}])
    );

    // Invalid overrides are refused.
    for invalid in [
        json!([{"client_mtu": 70000, "group_ids": [small.id]}]),
        json!([{"client_mtu": 50, "group_ids": [small.id]}]),
        json!([{"client_mtu": 1300, "group_ids": []}]),
        json!([{"client_mtu": 1300, "group_ids": [small.id]}, {"client_mtu": 1200, "group_ids": [small.id]}]),
        json!([{"client_mtu": 1300, "group_ids": [9999]}]),
    ] {
        let response = client
            .put(format!("/api/v1/network/{id}"))
            .json(&location("network", invalid.clone()))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{invalid}");
    }

    // Replacing them is audited with before and after.
    let response = client
        .put(format!("/api/v1/network/{id}"))
        .json(&location(
            "network",
            json!([{"client_mtu": 1300, "group_ids": [small.id]}, {"client_mtu": 1280, "group_ids": [smaller.id]}]),
        ))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let events = client.drain_all_events();
    assert!(
        events.iter().any(|(event, _, _)| matches!(
            event,
            ApiEventType::LocationGroupMtusChanged { before, after, .. }
                if before.len() == 1 && after.len() == 2
        )),
        "{events:?}"
    );

    // Omitting the field keeps the overrides and logs no MTU change.
    let mut keep = location("network", Value::Null);
    keep.as_object_mut().unwrap().remove("group_client_mtus");
    let response = client
        .put(format!("/api/v1/network/{id}"))
        .json(&keep)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !client
            .drain_all_events()
            .iter()
            .any(|(event, _, _)| matches!(event, ApiEventType::LocationGroupMtusChanged { .. }))
    );
    let details: Value = client
        .get(format!("/api/v1/network/{id}"))
        .send()
        .await
        .json()
        .await;
    assert_eq!(details["group_client_mtus"].as_array().unwrap().len(), 2);

    // An empty list clears them.
    let response = client
        .put(format!("/api/v1/network/{id}"))
        .json(&location("network", json!([])))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let details: Value = client
        .get(format!("/api/v1/network/{id}"))
        .send()
        .await
        .json()
        .await;
    assert_eq!(details["group_client_mtus"], json!([]));
}
