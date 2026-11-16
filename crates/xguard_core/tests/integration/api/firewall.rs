use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_common::gateway_event::GatewayCommand;

use super::common::{authenticate_admin, make_network, make_test_client, setup_pool};

fn rule(name: &str) -> Value {
    json!({
        "name": name,
        "action": "allow",
        "all_locations": true,
        "any_source": false,
        "all_users": true,
        "destinations": ["192.168.1.0/24", "10.0.0.7"],
        "protocols": [6],
        "ports": ["443", "8000-8080"],
    })
}

#[sqlx::test]
async fn test_firewall_rule_api(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, mut state) = make_test_client(pool).await;

    // Admins only.
    let response = client.get("/api/v1/firewall/rule").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    client.login_user("hpotter", "pass123").await;
    let response = client.get("/api/v1/firewall/rule").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    authenticate_admin(&mut client).await;

    // Invalid input is refused with a reason, and nothing is pushed to gateways.
    for bad in [
        json!({ "destinations": ["not-an-ip"] }),
        json!({ "ports": ["22"], "protocols": [1] }),
        json!({ "all_users": false }),
        json!({ "all_locations": false }),
    ] {
        let mut body = rule("bad");
        body.as_object_mut()
            .unwrap()
            .extend(bad.as_object().unwrap().clone());
        let response = client
            .post("/api/v1/firewall/rule")
            .json(&body)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    // A user that doesn't exist.
    let mut ghost = rule("ghost");
    ghost["all_users"] = json!(false);
    ghost["users"] = json!([424_242]);
    let response = client
        .post("/api/v1/firewall/rule")
        .json(&ghost)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(state.gateway_rx.try_recv().is_err());

    // Create: stored canonically, and gateways are told to re-check.
    let response = client
        .post("/api/v1/firewall/rule")
        .json(&rule("web"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = response.json().await;
    let id = created["id"].as_i64().unwrap();
    assert_eq!(
        created["destinations"],
        json!(["10.0.0.7", "192.168.1.0/24"])
    );
    assert_eq!(created["ports"], json!(["443", "8000-8080"]));
    assert!(matches!(
        state.gateway_rx.try_recv(),
        Ok(GatewayCommand::FirewallRulesChanged)
    ));

    // Update and read back.
    let mut changed = rule("web (updated)");
    changed["action"] = json!("reject");
    let response = client
        .put(format!("/api/v1/firewall/rule/{id}"))
        .json(&changed)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .get(format!("/api/v1/firewall/rule/{id}"))
        .send()
        .await;
    let fetched: Value = response.json().await;
    assert_eq!(fetched["name"], "web (updated)");
    assert_eq!(fetched["action"], "reject");
    assert!(matches!(
        state.gateway_rx.try_recv(),
        Ok(GatewayCommand::FirewallRulesChanged)
    ));

    let response = client.get("/api/v1/firewall/rule").send().await;
    let all: Vec<Value> = response.json().await;
    assert_eq!(all.len(), 1);

    // The audit log records each change.
    let response = client
        .get("/api/v1/activity_log?event=firewall_rule_added,firewall_rule_modified")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Delete, then it is gone.
    let response = client
        .delete(format!("/api/v1/firewall/rule/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .get(format!("/api/v1/firewall/rule/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = client
        .delete(format!("/api/v1/firewall/rule/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn test_location_policy_preview(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;

    let location: Value = make_network(&client, "office").await.json().await;
    let location_id = location["id"].as_i64().unwrap();

    // Firewall off and no SNAT: no policy.
    let response = client
        .get(format!("/api/v1/firewall/location/{location_id}/policy"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await, Value::Null);

    let response = client
        .get("/api/v1/firewall/location/999999/policy")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Firewall on, default deny, one rule for any source.
    sqlx::query("UPDATE wireguard_network SET acl_enabled = true WHERE id = $1")
        .bind(location_id)
        .execute(&state.pool)
        .await
        .unwrap();
    let mut open_web = rule("anyone to web");
    open_web["any_source"] = json!(true);
    let response = client
        .post("/api/v1/firewall/rule")
        .json(&open_web)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let policy: Value = client
        .get(format!("/api/v1/firewall/location/{location_id}/policy"))
        .send()
        .await
        .json()
        .await;
    assert_eq!(policy["default_action"], "Drop");
    assert_eq!(policy["rules"].as_array().unwrap().len(), 1);
    assert_eq!(policy["rules"][0]["destination_ranges"], 2);
    assert_eq!(policy["rules"][0]["source_ranges"], Value::Null);
    assert_eq!(policy["revision"].as_str().unwrap().len(), 32);
}

#[sqlx::test]
async fn test_snat_binding_api(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, mut state) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    let location: Value = make_network(&client, "office").await.json().await;
    let location_id = location["id"].as_i64().unwrap();
    let user_id: i64 = sqlx::query_scalar("SELECT id FROM \"user\" WHERE username = 'hpotter'")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    while state.gateway_rx.try_recv().is_ok() {}

    let binding =
        |ip: &str| json!({ "user_id": user_id, "location_id": location_id, "public_ip": ip });
    for bad in ["not-an-ip", "0.0.0.0", "127.0.0.1", "203.0.113.0/24"] {
        let response = client
            .post("/api/v1/firewall/snat")
            .json(&binding(bad))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }

    let response = client
        .post("/api/v1/firewall/snat")
        .json(&binding("203.0.113.7"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = response.json().await;
    assert_eq!(created["public_ip"], "203.0.113.7");
    let id = created["id"].as_i64().unwrap();
    assert!(matches!(
        state.gateway_rx.try_recv(),
        Ok(GatewayCommand::FirewallRulesChanged)
    ));

    // One binding per user and location.
    let response = client
        .post("/api/v1/firewall/snat")
        .json(&binding("203.0.113.8"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .put(format!("/api/v1/firewall/snat/{id}"))
        .json(&json!({ "public_ip": "2001:db8::7" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let all: Vec<Value> = client
        .get("/api/v1/firewall/snat")
        .send()
        .await
        .json()
        .await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["public_ip"], "2001:db8::7");

    let response = client
        .delete(format!("/api/v1/firewall/snat/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .delete(format!("/api/v1/firewall/snat/{id}"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
