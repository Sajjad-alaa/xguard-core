use reqwest::StatusCode;
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::common::{authenticate_admin, make_test_client, setup_pool};

#[sqlx::test]
async fn test_openid_endpoints(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool).await;

    // Nothing to offer without a provider.
    let response = client.get("/api/v1/openid/auth_info").send().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // A callback without a sign-in in progress is refused.
    let response = client
        .post("/api/v1/openid/callback")
        .json(&json!({ "code": "c", "state": "s" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Provider settings are admin-only and never return the secret.
    let provider = json!({
        "kind": "Google",
        "issuer": "https://accounts.google.com",
        "client_id": "client",
        "client_secret": "very-secret",
        "enabled": false,
    });
    let response = client
        .put("/api/v1/openid/provider")
        .json(&provider)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    client.login_user("hpotter", "pass123").await;
    let response = client
        .put("/api/v1/openid/provider")
        .json(&provider)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    authenticate_admin(&mut client).await;
    let response = client
        .put("/api/v1/openid/provider")
        .json(&provider)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = client
        .get("/api/v1/openid/provider")
        .send()
        .await
        .text()
        .await;
    assert!(!body.contains("very-secret"));
    assert!(body.contains("\"client_secret_set\":true"));

    // Disabled providers are not offered on the sign-in page.
    let response = client.get("/api/v1/openid/auth_info").send().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = client.delete("/api/v1/openid/provider").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = client.get("/api/v1/openid/provider").send().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
