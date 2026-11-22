//! XOAUTH2 against a mock token endpoint (speaking the OAuth 2.0 token endpoint protocol) and
//! the mock SMTP server, which checks the XOAUTH2 string lettre sends.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{Form, Json, Router, extract::State, http::StatusCode, routing::post};
use openidconnect::PkceCodeVerifier;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use xguard_common::{
    config::{SERVER_CONFIG, XGuardConfig},
    db::{models::settings::initialize_current_settings, setup_pool},
    testing::smtp::MockSmtpServer,
};

use super::*;
use crate::mail::{Mail, MailError};

static OVERRIDE: StdMutex<Option<Endpoints>> = StdMutex::new(None);

pub(super) fn endpoint_override() -> Option<Endpoints> {
    OVERRIDE.lock().ok()?.clone()
}

#[derive(Default)]
struct TokenEndpoint {
    /// Every form posted, in order.
    requests: StdMutex<Vec<HashMap<String, String>>>,
    issued: AtomicUsize,
    /// Answer refreshes with `invalid_grant`.
    revoked: std::sync::atomic::AtomicBool,
    /// Rotate the refresh token on refresh.
    rotate: std::sync::atomic::AtomicBool,
    expires_in: std::sync::atomic::AtomicU64,
}

async fn token(
    State(endpoint): State<Arc<TokenEndpoint>>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    endpoint.requests.lock().unwrap().push(form.clone());
    let n = endpoint.issued.fetch_add(1, Ordering::SeqCst) + 1;
    let expires_in = endpoint.expires_in.load(Ordering::SeqCst);
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            if form.get("code").map(String::as_str) != Some("good-code")
                || form.get("client_secret").map(String::as_str) != Some("client-secret")
                || form.get("code_verifier").is_none_or(|v| v.len() < 43)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "Bad code or verifier"
                    })),
                );
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": format!("access-{n}"),
                    "expires_in": expires_in,
                    "refresh_token": "refresh-1",
                    "token_type": "Bearer"
                })),
            )
        }
        Some("refresh_token") => {
            if endpoint.revoked.load(Ordering::SeqCst) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "Token has been expired or revoked."
                    })),
                );
            }
            let mut body = serde_json::json!({
                "access_token": format!("access-{n}"),
                "expires_in": expires_in,
                "token_type": "Bearer"
            });
            if endpoint.rotate.load(Ordering::SeqCst) {
                body["refresh_token"] = format!("refresh-{n}").into();
            }
            (StatusCode::OK, Json(body))
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported_grant_type" })),
        ),
    }
}

async fn start_token_endpoint() -> (Arc<TokenEndpoint>, Endpoints) {
    let endpoint = Arc::new(TokenEndpoint::default());
    endpoint.expires_in.store(3600, Ordering::SeqCst);
    let app = Router::new()
        .route("/token", post(token))
        .with_state(Arc::clone(&endpoint));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let endpoints = Endpoints {
        authorize: Url::parse("https://accounts.example.test/authorize").unwrap(),
        token: Url::parse(&format!("http://{addr}/token")).unwrap(),
    };
    (endpoint, endpoints)
}

fn query(url: &Url) -> HashMap<String, String> {
    url.query_pairs().into_owned().collect()
}

fn google_request() -> StartRequest {
    StartRequest {
        provider: Provider::Google,
        client_id: "client-id.apps.googleusercontent.com".into(),
        client_secret: Some("client-secret".into()),
        tenant_id: None,
        sender: "mailer@example.org".into(),
        tls_verify_cert: true,
    }
}

#[test]
fn providers_from_issuer() {
    assert_eq!(
        Provider::from_issuer("https://accounts.google.com"),
        Some(Provider::Google)
    );
    assert_eq!(
        Provider::from_issuer("https://login.microsoftonline.com/common"),
        Some(Provider::Microsoft)
    );
    assert_eq!(
        Provider::from_issuer("https://login.microsoftonline.com.evil.example/x"),
        None
    );
    assert_eq!(Provider::from_issuer("https://example.org"), None);
}

#[test]
fn redirect_uri_needs_https_or_loopback() {
    assert_eq!(
        redirect_uri("https://xguard.example.org/")
            .unwrap()
            .as_str(),
        "https://xguard.example.org/smtp-oauth-callback"
    );
    assert_eq!(
        redirect_uri("https://example.org/vpn?x=1")
            .unwrap()
            .as_str(),
        "https://example.org/vpn/smtp-oauth-callback"
    );
    assert!(redirect_uri("http://localhost:8000").is_ok());
    assert!(redirect_uri("http://127.0.0.1:8000").is_ok());
    assert!(redirect_uri("http://xguard.example.org").is_err());
    assert!(redirect_uri("not a url").is_err());
}

#[test]
fn provider_errors_are_sanitized() {
    assert_eq!(sanitize("bad\r\nline"), "bad  line");
    let long = "x".repeat(1000);
    assert!(sanitize(&long).chars().count() <= MAX_ERROR_LEN + 1);
}

#[test]
fn start_builds_a_pkce_authorization_url() {
    let mut settings = Settings::default();
    settings.xguard_url = "https://xguard.example.org".into();
    let url = start(9001, google_request(), &settings).unwrap();
    let params = query(&url);
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["client_id"], "client-id.apps.googleusercontent.com");
    assert_eq!(
        params["redirect_uri"],
        "https://xguard.example.org/smtp-oauth-callback"
    );
    assert_eq!(params["scope"], "https://mail.google.com/");
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["code_challenge"].len(), 43);
    assert_eq!(params["access_type"], "offline");
    assert_eq!(params["login_hint"], "mailer@example.org");
    assert!(params["state"].len() >= 40);
    // The client secret and verifier never appear in the URL.
    assert!(!url.as_str().contains("client-secret"));

    // Microsoft: tenant in the endpoint, validated.
    let mut request = google_request();
    request.provider = Provider::Microsoft;
    request.tenant_id = Some("contoso.onmicrosoft.com".into());
    let url = start(9002, request.clone(), &settings).unwrap();
    let params = query(&url);
    assert_eq!(
        params["scope"],
        "https://outlook.office.com/SMTP.Send offline_access"
    );
    request.tenant_id = Some("../evil".into());
    assert!(matches!(
        start(9002, request, &settings),
        Err(OAuthError::Invalid(_))
    ));

    // Bad input.
    let mut request = google_request();
    request.sender = "not-an-email".into();
    assert!(start(9003, request, &settings).is_err());
    let mut request = google_request();
    request.client_id = "has space".into();
    assert!(start(9003, request, &settings).is_err());
    // No secret given and none stored for this client.
    let mut request = google_request();
    request.client_secret = None;
    assert!(matches!(
        start(9003, request, &settings),
        Err(OAuthError::NotConfigured(_))
    ));
}

#[test]
fn settings_cannot_set_the_refresh_token() {
    let before = SmtpSettings {
        authentication: SmtpAuthentication::XOAuth2,
        oauth_issuer_url: Some(GOOGLE_ISSUER.into()),
        oauth_client_id: Some("client".into()),
        oauth_client_secret: Some("secret".to_owned().into()),
        oauth_refresh_token: Some("refresh".to_owned().into()),
        ..Default::default()
    };
    // Submitted with another refresh token: the stored one stays.
    let mut after = before.clone();
    after.oauth_refresh_token = Some("attacker".to_owned().into());
    after.sender = Some("other@example.org".into());
    protect_settings(&before, &mut after);
    assert_eq!(
        after.oauth_refresh_token.as_ref().unwrap().expose_secret(),
        "refresh"
    );
    // Another client: the grant no longer applies.
    let mut after = before.clone();
    after.oauth_client_id = Some("other".into());
    protect_settings(&before, &mut after);
    assert!(after.oauth_refresh_token.is_none());
    // Switching to password authentication drops the OAuth secrets.
    let mut after = before.clone();
    after.authentication = SmtpAuthentication::Login;
    protect_settings(&before, &mut after);
    assert!(after.oauth_refresh_token.is_none());
    assert!(after.oauth_client_secret.is_none());
}

/// The whole flow: connect a mailbox, send mail with XOAUTH2, reuse the cached access token,
/// refresh it shortly before expiry, save a rotated refresh token, and report a revoked grant.
#[sqlx::test]
async fn test_connect_and_send_with_xoauth2(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let _ = SERVER_CONFIG.set(XGuardConfig::new_test_config());
    initialize_current_settings(&pool).await.unwrap();
    let (endpoint, endpoints) = start_token_endpoint().await;
    *OVERRIDE.lock().unwrap() = Some(endpoints);
    clear_cache();

    let mut settings = Settings::get_current_settings();
    settings.xguard_url = "https://xguard.example.org".into();
    update_current_settings(&pool, settings.clone())
        .await
        .unwrap();

    // --- Connect. ---
    let url = start(1, google_request(), &settings).unwrap();
    let state = query(&url)["state"].clone();
    let challenge = query(&url)["code_challenge"].clone();

    // A wrong state, or another admin, gets nothing (and the right state still works once).
    assert!(matches!(
        finish(&pool, 1, "forged", Some("good-code"), None).await,
        Err(OAuthError::BadState)
    ));
    let url_other = start(2, google_request(), &settings).unwrap();
    let state_other = query(&url_other)["state"].clone();
    assert!(matches!(
        finish(&pool, 1, &state_other, Some("good-code"), None).await,
        Err(OAuthError::BadState)
    ));
    // Refused at the provider.
    let url_denied = start(3, google_request(), &settings).unwrap();
    let state_denied = query(&url_denied)["state"].clone();
    assert!(matches!(
        finish(&pool, 3, &state_denied, None, Some("access_denied")).await,
        Err(OAuthError::Denied(_))
    ));

    let connected = finish(&pool, 1, &state, Some("good-code"), None)
        .await
        .unwrap();
    assert_eq!(connected.provider, Provider::Google);
    assert_eq!(connected.sender, "mailer@example.org");
    // Single use.
    assert!(matches!(
        finish(&pool, 1, &state, Some("good-code"), None).await,
        Err(OAuthError::BadState)
    ));

    let exchange = endpoint.requests.lock().unwrap()[0].clone();
    assert_eq!(exchange["grant_type"], "authorization_code");
    assert_eq!(
        exchange["redirect_uri"],
        "https://xguard.example.org/smtp-oauth-callback"
    );
    // The verifier matches the challenge sent to the browser (S256).
    let verifier = PkceCodeVerifier::new(exchange["code_verifier"].clone());
    assert_eq!(
        PkceCodeChallenge::from_code_verifier_sha256(&verifier).as_str(),
        challenge
    );

    let stored = Settings::get_current_settings().smtp;
    assert_eq!(stored.authentication, SmtpAuthentication::XOAuth2);
    assert_eq!(stored.server.as_deref(), Some("smtp.gmail.com"));
    assert_eq!(stored.oauth_issuer_url.as_deref(), Some(GOOGLE_ISSUER));
    assert_eq!(
        stored.oauth_refresh_token.as_ref().unwrap().expose_secret(),
        "refresh-1"
    );
    // Never serialized.
    let json = serde_json::to_string(&Settings::get_current_settings()).unwrap();
    assert!(!json.contains("refresh-1") && !json.contains("client-secret"));

    // --- Send mail through the mock SMTP server with XOAUTH2. ---
    let smtp = MockSmtpServer::start().await;
    smtp.accept_xoauth2_token("access-1");
    smtp.accept_xoauth2_token("access-2");
    let mut settings = Settings::get_current_settings();
    settings.smtp.server = Some(smtp.addr().ip().to_string());
    settings.smtp.port = Some(i32::from(smtp.addr().port()));
    settings.smtp.encryption = SmtpEncryption::None;
    update_current_settings(&pool, settings).await.unwrap();
    register_pool(&pool);

    // The token from the exchange (access-1; the three rejected finish() calls failed before token_request) is cached.
    let mail = || {
        Mail::new(
            "someone@example.org",
            "XOAUTH2 test".into(),
            "<p>hi</p>".into(),
            "hi".into(),
        )
    };
    mail().send().await.unwrap();
    mail().send().await.unwrap();
    assert_eq!(smtp.wait_for_count(2).await.len(), 2);
    let auth = smtp.xoauth2();
    assert_eq!(auth.len(), 2);
    assert_eq!(
        auth[0],
        "user=mailer@example.org\x01auth=Bearer access-1\x01\x01"
    );
    assert_eq!(
        endpoint.issued.load(Ordering::SeqCst),
        1,
        "the cached access token was reused"
    );

    // --- Shortly before expiry it is refreshed, once for concurrent mails. ---
    endpoint.rotate.store(true, Ordering::SeqCst);
    if let Some(entry) = CACHE.lock().unwrap().as_mut() {
        entry.expires_at = Instant::now() + EXPIRY_MARGIN / 2;
    }
    let (first, second) = tokio::join!(mail().send(), mail().send());
    first.unwrap();
    second.unwrap();
    assert_eq!(endpoint.issued.load(Ordering::SeqCst), 2, "one refresh");
    let refresh = endpoint.requests.lock().unwrap()[1].clone();
    assert_eq!(refresh["grant_type"], "refresh_token");
    assert_eq!(refresh["refresh_token"], "refresh-1");
    assert_eq!(refresh["client_secret"], "client-secret");
    assert!(smtp.xoauth2()[2].contains("Bearer access-2"));
    // The rotated refresh token was saved.
    assert_eq!(
        Settings::get_current_settings()
            .smtp
            .oauth_refresh_token
            .unwrap()
            .expose_secret(),
        "refresh-2"
    );

    // --- A revoked grant gives a clear error. ---
    endpoint.revoked.store(true, Ordering::SeqCst);
    clear_cache();
    let err = mail().send().await.unwrap_err();
    let MailError::OAuth2(OAuthError::Provider(message)) = &err else {
        panic!("expected a provider error, got {err:?}");
    };
    assert!(message.contains("invalid_grant"), "{message}");
    assert!(err.to_string().contains("connect the mailbox again"));

    // --- A token the SMTP server refuses fails the send. ---
    endpoint.revoked.store(false, Ordering::SeqCst);
    endpoint.rotate.store(false, Ordering::SeqCst);
    clear_cache();
    assert!(mail().send().await.is_err(), "access-4 is not accepted");

    *OVERRIDE.lock().unwrap() = None;
}
