//! Desktop client provisioning files: admin only, short-lived single-use tokens, audited.

use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_core::{db::models::enrollment::Token, events::ApiEventType};

use super::common::{authenticate_admin, make_test_client, setup_pool};

#[sqlx::test]
async fn test_provisioning_file(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, client_state) = make_test_client(pool).await;

    // Users cannot create provisioning files, not even for themselves.
    client.login_user("hpotter", "pass123").await;
    let response = client
        .post("/api/v1/user/hpotter/provisioning")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    authenticate_admin(&mut client).await;
    client.drain_all_events();
    for body in [
        json!({"valid_hours": 0}),
        json!({"valid_hours": 169}),
        json!({"valid_hours": 2, "extra": true}),
    ] {
        let response = client
            .post("/api/v1/user/hpotter/provisioning")
            .json(&body)
            .send()
            .await;
        assert!(
            response.status().is_client_error(),
            "{body} must be refused, got {}",
            response.status()
        );
    }
    let response = client
        .post("/api/v1/user/nobody/provisioning")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(client.drain_all_events().is_empty());

    let response = client
        .post("/api/v1/user/hpotter/provisioning")
        .json(&json!({"valid_hours": 2}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let file: Value = response.json().await;
    assert_eq!(file["version"], 1);
    assert_eq!(file["username"], "hpotter");
    let token = file["enrollment_token"].as_str().unwrap();
    assert!(file["enrollment_url"].as_str().unwrap().starts_with("http"));
    let expires_at: DateTime<Utc> = file["expires_at"].as_str().unwrap().parse().unwrap();
    let hours = (expires_at - Utc::now()).num_minutes();
    assert!(
        (115..=120).contains(&hours),
        "about two hours, got {hours} minutes"
    );

    // The token is a single-use desktop activation token bound to the user.
    let tokens = Token::fetch_all(&client_state.pool).await.unwrap();
    let stored = tokens.iter().find(|t| t.id == token).expect("token stored");
    assert!(stored.used_at.is_none());
    assert_eq!(stored.token_type.as_deref(), Some("ENROLLMENT"));
    assert!((stored.expires_at - Utc::now().naive_utc()).num_minutes() <= 120);

    let events = client.drain_all_events();
    let [(ApiEventType::ProvisioningFileCreated { user, .. }, _, _)] = events.as_slice() else {
        panic!("expected one provisioning event, got {events:?}");
    };
    assert_eq!(user.username, "hpotter");

    // A new file replaces the previous unused token.
    let response = client
        .post("/api/v1/user/hpotter/provisioning")
        .json(&json!({}))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let tokens = Token::fetch_all(&client_state.pool).await.unwrap();
    assert!(tokens.iter().all(|t| t.id != token), "old token removed");
}
