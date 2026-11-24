use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, DeviceType,
            device_posture::{LocationPostures, PostureSnapshot},
        },
    },
    gateway_event::GatewayCommand,
};
use xguard_core::events::ApiEventType;

use super::common::{authenticate_admin, get_db_user, make_network, make_test_client, setup_pool};

/// The body of a location update, from the location's details.
async fn location_body(client: &super::common::client::TestClient, location_id: Id) -> Value {
    let response = client
        .get(format!("/api/v1/network/{location_id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut location: Value = response.json().await;
    let data = location.as_object_mut().unwrap();
    for field in ["id", "gateways", "has_devices"] {
        data.remove(field);
    }
    for field in ["address", "allowed_ips"] {
        let joined = data[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(",");
        data.insert(field.into(), Value::String(joined));
    }
    data.insert("mfa_flows".into(), json!([]));
    location
}

fn policy(name: &str) -> Value {
    json!({
        "name": name,
        "description": "Company laptops",
        "min_desktop_client_version": "2.2.0",
        "os_rules": [
            {"os_type": "linux", "min_kernel_version": "6.1", "disk_encryption_required": true,
             "firewall_required": true},
            {"os_type": "windows", "min_os_version": 11, "screen_lock_required": true},
        ],
    })
}

#[sqlx::test]
async fn test_device_posture_api(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, mut state) = make_test_client(pool.clone()).await;

    // Admins only.
    let response = client.get("/api/v1/device-posture").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    client.login_user("hpotter", "pass123").await;
    for path in [
        "/api/v1/device-posture",
        "/api/v1/device-posture/versions",
        "/api/v1/user/hpotter/device-posture",
    ] {
        let response = client.get(path).send().await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let response = client
        .post("/api/v1/device-posture")
        .json(&policy("p"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    authenticate_admin(&mut client).await;
    client.drain_all_events();

    // Invalid input is refused with a reason and nothing is stored or audited.
    for bad in [
        json!({"name": ""}),
        json!({"name": "<script>"}),
        json!({"name": "ok", "min_desktop_client_version": "two"}),
        json!({"name": "ok", "os_rules": [{"os_type": "linux"}, {"os_type": "linux"}]}),
        json!({"name": "ok", "os_rules": [{"os_type": "macos", "min_os_version": "14.x"}]}),
        json!({"name": "ok", "os_rules": [{"os_type": "windows", "windows_security_update_max_age": 0}]}),
        json!({"name": "ok", "description": "d".repeat(513)}),
    ] {
        let response = client
            .post("/api/v1/device-posture")
            .json(&bad)
            .send()
            .await;
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}: {}",
            response.status()
        );
    }
    // Unknown fields for an operating system are refused while parsing.
    let response = client
        .post("/api/v1/device-posture")
        .json(
            &json!({"name": "ok", "os_rules": [{"os_type": "linux", "device_integrity_required": true}]}),
        )
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    client.assert_event_queue_is_empty();

    // Create: stored canonically and audited.
    let response = client
        .post("/api/v1/device-posture")
        .json(&policy("Laptops"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = response.json().await;
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["name"], "Laptops");
    assert_eq!(created["locations"], json!([]));
    assert_eq!(created["os_rules"][0]["os_type"], "windows");
    assert_eq!(created["os_rules"][0]["min_os_version"], "10.0.22000");
    assert_eq!(created["os_rules"][1]["os_type"], "linux");
    assert_eq!(created["os_rules"][1]["min_kernel_version"], "6.1");
    let events = client.drain_all_events();
    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0].0, ApiEventType::DevicePostureCreated { posture } if posture.id == id)
    );

    let response = client
        .get(format!("/api/v1/device-posture/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: Value = response.json().await;
    assert_eq!(fetched, created);
    let response = client.get("/api/v1/device-posture/9999").send().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = client.get("/api/v1/device-posture/versions").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let versions: Value = response.json().await;
    assert!(versions["windows"].as_array().unwrap().len() > 2);

    // Attach to a location (non-MFA): its peers become session-authorized, so the gateway
    // gets the new (empty) peer list.
    let location: Value = make_network(&client, "office").await.json().await;
    let location_id = location["id"].as_i64().unwrap();
    client.drain_all_events();
    while state.gateway_rx.try_recv().is_ok() {}
    let response = client
        .put(format!("/api/v1/device-posture/{id}/locations"))
        .json(&json!({"locations": [location_id, location_id]}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let updated: Value = response.json().await;
    assert_eq!(updated["locations"], json!([location_id]));
    match state.gateway_rx.try_recv() {
        Ok(GatewayCommand::NetworkModified(network, peers)) => {
            assert_eq!(network.id, location_id);
            assert!(peers.is_empty());
        }
        other => panic!("expected NetworkModified, got {other:?}"),
    }
    let events = client.drain_all_events();
    assert!(matches!(
        &events[..],
        [(ApiEventType::DevicePostureLocationsAssigned { posture_id, location_ids, .. }, _, _)]
            if *posture_id == id && location_ids == &vec![location_id]
    ));
    // The location reports its policies.
    let response = client
        .get(format!("/api/v1/network/{location_id}"))
        .send()
        .await;
    let details: Value = response.json().await;
    assert_eq!(details["posture_checks"], json!([id]));
    // Unknown locations are refused; the same assignment again changes nothing.
    let response = client
        .put(format!("/api/v1/device-posture/{id}/locations"))
        .json(&json!({"locations": [424_242]}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = client
        .put(format!("/api/v1/device-posture/{id}/locations"))
        .json(&json!({"locations": [location_id]}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    client.assert_event_queue_is_empty();
    assert!(state.gateway_rx.try_recv().is_err());

    // Update: audited with before and after; identical updates are not.
    let mut body = policy("Laptops");
    body["os_rules"][0]["min_kernel_version"] = json!("6.6");
    let response = client
        .put(format!("/api/v1/device-posture/{id}"))
        .json(&body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let after: Value = response.json().await;
    assert_eq!(after["os_rules"][1]["min_kernel_version"], "6.6");
    assert_eq!(after["locations"], json!([location_id]));
    let events = client.drain_all_events();
    assert!(matches!(
        &events[..],
        [(ApiEventType::DevicePostureUpdated { .. }, _, _)]
    ));
    let response = client
        .put(format!("/api/v1/device-posture/{id}"))
        .json(&body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    client.assert_event_queue_is_empty();

    // Duplicate: same rules, no locations.
    let response = client
        .post(format!("/api/v1/device-posture/{id}/duplicate"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let copy: Value = response.json().await;
    assert_eq!(copy["name"], "Laptops (copy)");
    assert_eq!(copy["os_rules"], after["os_rules"]);
    assert_eq!(copy["locations"], json!([]));
    let copy_id = copy["id"].as_i64().unwrap();
    let events = client.drain_all_events();
    assert!(matches!(
        &events[..],
        [(ApiEventType::DevicePostureDuplicated { .. }, _, _)]
    ));

    let response = client.get("/api/v1/device-posture").send().await;
    let list: Vec<Value> = response.json().await;
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["id"], id);

    // Location side: attach both through the location form.
    let mut location_body = location_body(&client, location_id).await;
    location_body["posture_checks"] = json!([copy_id, id]);
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&location_body)
        .send()
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await
    );
    assert_eq!(
        LocationPostures::find(&pool, location_id).await.unwrap(),
        vec![id, copy_id]
    );
    let events = client.drain_all_events();
    assert!(events.iter().any(|(event, _, _)| matches!(
        event,
        ApiEventType::LocationPosturesAssigned { posture_ids, .. } if posture_ids == &vec![id, copy_id]
    )));
    // Unknown policies are refused.
    location_body["posture_checks"] = json!([987_654]);
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&location_body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Leaving the field out keeps the assignments.
    location_body
        .as_object_mut()
        .unwrap()
        .remove("posture_checks");
    let response = client
        .put(format!("/api/v1/network/{location_id}"))
        .json(&location_body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        LocationPostures::find(&pool, location_id).await.unwrap(),
        vec![id, copy_id]
    );
    client.drain_all_events();

    // Delete: the location still has the copy, so no gateway update is needed.
    while state.gateway_rx.try_recv().is_ok() {}
    let response = client
        .delete(format!("/api/v1/device-posture/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.gateway_rx.try_recv().is_err());
    let events = client.drain_all_events();
    assert!(matches!(
        &events[..],
        [(ApiEventType::DevicePostureDeleted { .. }, _, _)]
    ));
    // Deleting the last policy relaxes the location again.
    let response = client
        .delete(format!("/api/v1/device-posture/{copy_id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(matches!(
        state.gateway_rx.try_recv(),
        Ok(GatewayCommand::NetworkModified(network, _)) if network.id == location_id
    ));
    let response = client
        .delete(format!("/api/v1/device-posture/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn test_device_posture_all_platform_checks(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;

    // The catalog offers client releases for the dropdowns.
    let response = client.get("/api/v1/device-posture/versions").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let catalog: Value = response.json().await;
    for list in ["desktop_client", "mobile_client"] {
        let values: Vec<&str> = catalog[list]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["value"].as_str().unwrap())
            .collect();
        assert_eq!(values, ["2.2.0", "2.3.0", "2.3.1"], "{list}");
    }
    assert_eq!(catalog["windows"][0]["label"], "Windows 10 22H2");

    let body = json!({
        "name": "Everywhere",
        "min_mobile_client_version": "2.3.1",
        "os_rules": [
            {"os_type": "windows", "windows_security_update_max_age": 30, "antivirus_required": true},
            {"os_type": "macos", "antivirus_required": true, "ad_domain_joined_required": true,
             "security_update_max_age": 60},
            {"os_type": "linux", "antivirus_required": true, "ad_domain_joined_required": true,
             "security_update_max_age": 14},
            {"os_type": "ios", "screen_lock_required": true, "disk_encryption_required": true},
            {"os_type": "android", "screen_lock_required": true, "disk_encryption_required": true,
             "android_security_patch_level_max_age": 90},
        ],
    });
    let response = client
        .post("/api/v1/device-posture")
        .json(&body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = response.json().await;
    let id = created["id"].as_i64().unwrap();

    let response = client
        .get(format!("/api/v1/device-posture/{id}"))
        .send()
        .await;
    let stored: Value = response.json().await;
    let rule = |os: &str| {
        stored["os_rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["os_type"] == os)
            .unwrap()
            .clone()
    };
    assert_eq!(rule("windows")["windows_security_update_max_age"], 30);
    assert!(rule("windows").get("security_update_max_age").is_none());
    for os in ["macos", "linux"] {
        assert_eq!(rule(os)["antivirus_required"], true, "{os}");
        assert_eq!(rule(os)["ad_domain_joined_required"], true, "{os}");
    }
    assert_eq!(rule("macos")["security_update_max_age"], 60);
    assert_eq!(rule("linux")["security_update_max_age"], 14);
    for os in ["ios", "android"] {
        assert_eq!(rule(os)["screen_lock_required"], true, "{os}");
        assert_eq!(rule(os)["disk_encryption_required"], true, "{os}");
    }
    assert_eq!(rule("android")["android_security_patch_level_max_age"], 90);

    // Stored in the renamed column, which keeps the 1-3650 day range.
    let ages: Vec<(String, Option<i32>)> = sqlx::query_as(
        "SELECT os_type::text, security_update_max_age FROM device_posture_os_rule \
         WHERE posture_id = $1 ORDER BY device_posture_os_rule.os_type",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        ages,
        [
            ("windows".into(), Some(30)),
            ("macos".into(), Some(60)),
            ("linux".into(), Some(14)),
            ("ios".into(), None),
            ("android".into(), None),
        ]
    );
    let out_of_range = sqlx::query(
        "UPDATE device_posture_os_rule SET security_update_max_age = 0 WHERE posture_id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await;
    assert!(out_of_range.is_err());
}

#[sqlx::test]
async fn test_device_posture_snapshot_view(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool.clone()).await;
    authenticate_admin(&mut client).await;

    let user = get_db_user(&pool, "hpotter").await;
    let device = Device::new(
        "laptop".into(),
        "kQRWxvJkSRvfxxpDEkPYRnimpvX1ZqmBzmxeocBpi14=".into(),
        user.id,
        DeviceType::User,
        None,
        true,
    )
    .save(&pool)
    .await
    .unwrap();

    let response = client
        .get(format!("/api/v1/device/{}/posture", device.id))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = response.json().await;
    assert_eq!(view["device_name"], "laptop");
    assert_eq!(view["snapshot"], Value::Null);

    PostureSnapshot {
        device_id: device.id,
        facts: json!({"os": "linux", "disk_encrypted": false}),
        reported_at: chrono::Utc::now().naive_utc(),
        location_id: None,
        compliant: false,
        failed_checks: vec!["disk encryption is required".into()],
    }
    .upsert(&pool)
    .await
    .unwrap();
    let response = client
        .get(format!("/api/v1/device/{}/posture", device.id))
        .send()
        .await;
    let view: Value = response.json().await;
    assert_eq!(view["snapshot"]["compliant"], false);
    assert_eq!(view["snapshot"]["facts"]["os"], "linux");
    assert_eq!(
        view["snapshot"]["failed_checks"],
        json!(["disk encryption is required"])
    );

    let response = client
        .get("/api/v1/user/hpotter/device-posture")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let list: Vec<PostureSnapshot> = response.json().await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].device_id, device.id);
    let response = client
        .get("/api/v1/user/nobody/device-posture")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let missing: Id = 999_999;
    let response = client
        .get(format!("/api/v1/device/{missing}/posture"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
