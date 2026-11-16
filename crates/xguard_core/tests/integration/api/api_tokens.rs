use reqwest::{StatusCode, header::AUTHORIZATION};
use serde_json::{Value, json};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use xguard_common::db::models::{ApiToken, group::Group};
use xguard_core::events::ApiEventType;

use super::common::{
    authenticate_admin, client::TestClient, get_db_user, make_test_client, setup_pool,
};

async fn create_token(client: &mut TestClient, username: &str, body: Value) -> (String, i64) {
    let response = client
        .post(format!("/api/v1/user/{username}/api_token"))
        .json(&body)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = response.json().await;
    let token = created["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("xgt_"));
    assert_eq!(created["api_token"]["hint"], json!(token[..8]));
    assert!(matches!(
        client.drain_all_events().as_slice(),
        [(ApiEventType::ApiTokenAdded { .. }, _, _)]
    ));
    (token, created["api_token"]["id"].as_i64().unwrap())
}

async fn logout(client: &mut TestClient) {
    let response = client.post("/api/v1/auth/logout").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    client.drain_all_events();
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn token_count(pool: &PgPool, username: &str) -> usize {
    let user = get_db_user(pool, username).await;
    ApiToken::find_by_user(pool, user.id).await.unwrap().len()
}

#[sqlx::test]
async fn test_api_token_lifecycle(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool.clone()).await;

    // Admins only.
    client.login_user("hpotter", "pass123").await;
    let response = client.get("/api/v1/user/hpotter/api_token").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    authenticate_admin(&mut client).await;

    // Tokens are created for your own account only, with a valid name and lifetime.
    let response = client
        .post("/api/v1/user/hpotter/api_token")
        .json(&json!({ "name": "theirs" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for bad in [
        json!({ "name": "  " }),
        json!({ "name": "x".repeat(65) }),
        json!({ "name": "ci", "expires_in_days": 0 }),
        json!({ "name": "ci", "expires_in_days": 367 }),
    ] {
        let response = client
            .post("/api/v1/user/admin/api_token")
            .json(&bad)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    client.assert_event_queue_is_empty();

    let (token, token_id) = create_token(&mut client, "admin", json!({ "name": "ci" })).await;
    let (read_only, read_only_id) = create_token(
        &mut client,
        "admin",
        json!({ "name": "monitoring", "read_only": true, "expires_in_days": 30 }),
    )
    .await;

    // Listing never reveals a token or its hash.
    let response = client.get("/api/v1/user/admin/api_token").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await;
    assert!(!body.contains(&token[8..]) && !body.contains("hash"));
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(listed[0]["name"], "monitoring");
    assert_eq!(listed[0]["read_only"], true);
    assert!(listed[0]["expires_at"].is_string());
    assert!(listed[1]["last_used_at"].is_null());

    // Without the session, the token authenticates.
    logout(&mut client).await;
    let response = client.get("/api/v1/user").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = client
        .get("/api/v1/user")
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let used = ApiToken::find_for_user(&pool, token_id, 1).await.unwrap();
    let used = used.unwrap();
    assert!(used.last_used_at.is_some() && used.last_used_ip.is_some());
    for bad in ["xgt_short", &token.replace("xgt_", "dgt_"), "", "Basic abc"] {
        let response = client
            .get("/api/v1/user")
            .header(AUTHORIZATION, &bearer(bad))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{bad}");
    }

    // A token cannot mint more tokens.
    let response = client
        .post("/api/v1/user/admin/api_token")
        .header(AUTHORIZATION, &bearer(&token))
        .json(&json!({ "name": "child" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A read-only token can read but not change anything.
    let response = client
        .get("/api/v1/user/admin/api_token")
        .header(AUTHORIZATION, &bearer(&read_only))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .post(format!("/api/v1/user/admin/api_token/{token_id}/rename"))
        .header(AUTHORIZATION, &bearer(&read_only))
        .json(&json!({ "name": "renamed" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A full token can rename and revoke; a revoked token stops working at once.
    let response = client
        .post(format!("/api/v1/user/admin/api_token/{token_id}/rename"))
        .header(AUTHORIZATION, &bearer(&token))
        .json(&json!({ "name": "ci-main" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let renamed: Value = response.json().await;
    assert_eq!(renamed["name"], "ci-main");
    let response = client
        .delete(format!("/api/v1/user/admin/api_token/{read_only_id}"))
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let events = client.drain_all_events();
    assert!(matches!(
        events.as_slice(),
        [
            (ApiEventType::ApiTokenRenamed { old_name, new_name, .. }, Some(1), _),
            (ApiEventType::ApiTokenRemoved { .. }, Some(1), _),
        ] if old_name == "ci" && new_name == "ci-main"
    ));
    let response = client
        .get("/api/v1/user")
        .header(AUTHORIZATION, &bearer(&read_only))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = client
        .delete(format!("/api/v1/user/admin/api_token/{read_only_id}"))
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // An expired token is refused.
    sqlx::query("UPDATE api_token SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .unwrap();
    let response = client
        .get("/api/v1/user")
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn test_api_tokens_are_revoked_with_admin_rights(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool.clone()).await;
    let admin_group = Group::find_by_name(&pool, "admin").await.unwrap().unwrap();
    let hpotter = get_db_user(&pool, "hpotter").await;
    hpotter.add_to_group(&pool, &admin_group).await.unwrap();

    // Losing admin rights revokes the user's tokens the next time one is used.
    client.login_user("hpotter", "pass123").await;
    let (token, _) = create_token(&mut client, "hpotter", json!({ "name": "a" })).await;
    create_token(&mut client, "hpotter", json!({ "name": "b" })).await;
    hpotter
        .remove_from_group(&pool, &admin_group)
        .await
        .unwrap();
    let response = client
        .get("/api/v1/user")
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(token_count(&pool, "hpotter").await, 0);

    // Disabling a user revokes their tokens.
    hpotter.add_to_group(&pool, &admin_group).await.unwrap();
    client.login_user("hpotter", "pass123").await;
    let (token, _) = create_token(&mut client, "hpotter", json!({ "name": "c" })).await;
    authenticate_admin(&mut client).await;
    let response = client
        .post("/api/v1/user/bulk-disable")
        .json(&json!({ "users": [hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(token_count(&pool, "hpotter").await, 0);
    let response = client
        .get("/api/v1/user")
        .header(AUTHORIZATION, &bearer(&token))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // So does disabling them from the user form.
    let response = client
        .post("/api/v1/user/bulk-enable")
        .json(&json!({ "users": [hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    create_token(&mut client, "hpotter", json!({ "name": "d" })).await;
    authenticate_admin(&mut client).await;
    let response = client.get("/api/v1/user/hpotter").send().await;
    let mut details: Value = response.json().await;
    let mut user = details["user"].take();
    user["is_active"] = json!(false);
    let response = client.put("/api/v1/user/hpotter").json(&user).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(token_count(&pool, "hpotter").await, 0);
}
