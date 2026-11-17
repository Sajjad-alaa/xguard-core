//! Cloud directory sync through the API, against a mock Okta that speaks the real protocol.

use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_core::events::ApiEventType;

use super::common::{authenticate_admin, get_db_user, make_test_client, setup_pool};

#[path = "../../../src/dirsync/tests/mocks.rs"]
#[allow(dead_code)]
mod mocks;

use mocks::{Fixture, Status};

fn provider(issuer: &str, with_secrets: bool) -> Value {
    let mut body = json!({
        "kind": "Okta",
        "issuer": issuer,
        "client_id": "sign-in",
        "enabled": true,
        "directory_sync_enabled": true,
        "directory_sync_interval": 3600,
        "directory_sync_user_behavior": "disable",
        "directory_sync_admin_behavior": "keep",
        "directory_sync_target": "all",
        "directory_sync_group_match": ["Eng*", "Sales"],
        "directory_sync_user_groups": [],
        "prefetch_users": true,
        "okta_dirsync_client_id": mocks::OKTA_CLIENT_ID,
    });
    if with_secrets {
        body["client_secret"] = json!("sign-in-secret");
        body["okta_private_jwk"] = json!(mocks::okta_jwk());
    }
    body
}

#[sqlx::test]
async fn test_directory_sync_api(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, state) = make_test_client(pool).await;
    let mock = mocks::start(
        Fixture::default()
            .user("u1", "alice@example.org", Status::Active)
            .user("u2", "bob@example.org", Status::Suspended)
            .group("g1", "Engineering", &["u1"])
            .group("g2", "Marketing", &["u1"]),
    )
    .await;

    // Admins only.
    client.login_user("hpotter", "pass123").await;
    for path in [
        "/api/v1/openid/provider/sync/test",
        "/api/v1/openid/provider/sync/dry_run",
    ] {
        let response = client
            .post(path)
            .json(&provider(&mock.base, true))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = client
        .post("/api/v1/openid/provider/sync")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    authenticate_admin(&mut client).await;
    client.drain_all_events();

    // Settings are saved; secrets are never returned.
    let response = client
        .put("/api/v1/openid/provider")
        .json(&provider(&mock.base, true))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = client
        .get("/api/v1/openid/provider")
        .send()
        .await
        .json::<Value>()
        .await;
    assert_eq!(body["okta_private_jwk_set"], true);
    assert_eq!(body["directory_sync_user_behavior"], "disable");
    assert_eq!(body["directory_sync_group_match"], json!(["Eng*", "Sales"]));
    let text = body.to_string();
    assert!(!text.contains("\"d\"") && !text.contains("okta_private_jwk\""));

    // The test reuses the stored key when none is sent.
    let response = client
        .post("/api/v1/openid/provider/sync/test")
        .json(&provider(&mock.base, false))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await,
        json!({ "users": 2, "groups": 2 })
    );
    let response = client
        .post("/api/v1/openid/provider/sync/test")
        .json(&json!({
            "kind": "Okta", "issuer": mock.base, "client_id": "sign-in",
            "directory_sync_enabled": true, "okta_dirsync_client_id": "someone-else",
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = response.json::<Value>().await["msg"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        message.contains("refused XGuard's credentials"),
        "{message}"
    );

    // A dry run changes nothing.
    let response = client
        .post("/api/v1/openid/provider/sync/dry_run")
        .json(&provider(&mock.base, false))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = response.json::<Value>().await;
    assert_eq!(report["applied"], false);
    assert_eq!(report["plan"]["create_users"][0]["username"], "alice");
    assert_eq!(
        report["plan"]["add_members"],
        json!([{ "group": "Engineering", "username": "alice" }])
    );
    assert!(
        sqlx::query_scalar::<_, i64>(r#"SELECT count(*) FROM "user" WHERE username = 'alice'"#)
            .fetch_one(&state.pool)
            .await
            .unwrap()
            == 0
    );

    // Sync now.
    let response = client
        .post("/api/v1/openid/provider/sync")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = response.json::<Value>().await;
    assert_eq!(report["applied"], true);
    assert_eq!(report["errors"], json!([]));
    let alice = get_db_user(&state.pool, "alice").await;
    assert_eq!(alice.email, "alice@example.org");
    assert_eq!(
        alice.member_of_names(&state.pool).await.unwrap(),
        ["Engineering"]
    );
    let status = client
        .get("/api/v1/openid/provider/sync/status")
        .send()
        .await
        .json::<Value>()
        .await;
    assert_eq!(status["enabled"], true);
    assert_eq!(status["last_run"]["success"], true);

    // Every admin action is in the activity log.
    let events: Vec<ApiEventType> = client
        .drain_all_events()
        .into_iter()
        .map(|(event, _, _)| event)
        .collect();
    let kinds: Vec<String> = events
        .iter()
        .map(|event| match event {
            ApiEventType::OpenIdProviderModified { .. } => "modified".into(),
            ApiEventType::DirectorySyncTested { success, .. } => format!("tested {success}"),
            ApiEventType::DirectorySyncStarted { dry_run, .. } => format!("started {dry_run}"),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "modified",
            "tested true",
            "tested false",
            "started true",
            "started false"
        ]
    );

    // Turned off, "sync now" is refused.
    let mut off = provider(&mock.base, false);
    off["directory_sync_enabled"] = json!(false);
    let response = client
        .put("/api/v1/openid/provider")
        .json(&off)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .post("/api/v1/openid/provider/sync")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Plain HTTP to another host is refused for the issuer, so credentials never leave
    // unencrypted.
    let mut insecure = provider("http://idp.example.org", false);
    insecure["client_secret"] = json!("x");
    let response = client
        .post("/api/v1/openid/provider/sync/test")
        .json(&insecure)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
