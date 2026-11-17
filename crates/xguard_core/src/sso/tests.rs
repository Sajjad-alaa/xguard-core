//! The OpenID flow against a mock provider that speaks the real protocol: discovery, JWKS,
//! PKCE-checked token endpoint and RS256-signed ID tokens.

use std::sync::{Arc, Mutex};

use axum::{
    Form, Json, Router,
    extract::State,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{EncodingKey, Header, encode};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use xguard_common::db::{
    models::{Settings, User, settings::update_current_settings},
    setup_pool,
};

use super::{
    LinkError,
    flow::{self, FlowError, Identity},
    provider::{OpenIdProvider, ProviderConfig, ProviderInput, ProviderKind},
    resolve_user, username_base,
};

const CLIENT_ID: &str = "xguard-test";
const REDIRECT: &str = "http://localhost:8000/auth/callback";

#[derive(Default)]
struct Expected {
    challenge: String,
    nonce: String,
    /// Sign with a key the provider does not publish.
    forge: bool,
}

#[derive(Clone)]
struct MockProvider {
    issuer: String,
    key: Arc<RsaPrivateKey>,
    forger: Arc<RsaPrivateKey>,
    expected: Arc<Mutex<Expected>>,
}

async fn discovery(State(mock): State<MockProvider>) -> Json<Value> {
    Json(json!({
        "issuer": mock.issuer,
        "authorization_endpoint": format!("{}/authorize", mock.issuer),
        "token_endpoint": format!("{}/token", mock.issuer),
        "jwks_uri": format!("{}/jwks", mock.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks(State(mock): State<MockProvider>) -> Json<Value> {
    let public = mock.key.to_public_key();
    Json(json!({ "keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    }]}))
}

async fn token(
    State(mock): State<MockProvider>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let expected = mock.expected.lock().unwrap();
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if form.get("code").map(String::as_str) != Some("the-code") || challenge != expected.challenge {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": mock.issuer, "sub": "subject-1", "aud": CLIENT_ID,
        "iat": now, "exp": now + 300, "nonce": expected.nonce,
        "email": "jane@example.org", "email_verified": true,
        "given_name": "Jane", "family_name": "Doe", "preferred_username": "Jane.Doe@example.org",
    });
    let signer = if expected.forge {
        &mock.forger
    } else {
        &mock.key
    };
    let pem = signer.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k1".into());
    let id_token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    Ok(Json(json!({
        "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token,
    })))
}

async fn start_mock() -> MockProvider {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let mut rng = rand::thread_rng();
    let mock = MockProvider {
        issuer,
        key: Arc::new(RsaPrivateKey::new(&mut rng, 2048).unwrap()),
        forger: Arc::new(RsaPrivateKey::new(&mut rng, 2048).unwrap()),
        expected: Arc::default(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    mock
}

fn config(issuer: &str) -> ProviderConfig {
    ProviderConfig {
        provider: OpenIdProvider {
            id: 1,
            kind: ProviderKind::Custom,
            issuer: issuer.to_owned(),
            client_id: CLIENT_ID.into(),
            enabled: true,
            display_name: None,
            disable_password_management: false,
            client_secret_set: true,
            directory_sync: crate::dirsync::settings::DirectorySyncSettings::default(),
        },
        client_secret: "secret".into(),
        directory_secrets: crate::dirsync::settings::DirectorySyncSecrets::default(),
    }
}

fn query_param(url: &str, name: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap()
}

#[tokio::test]
async fn test_code_flow_with_pkce_and_signature_checks() {
    let mock = start_mock().await;
    let config = config(&mock.issuer);

    let (url, pending) = flow::start(&config, REDIRECT).await.unwrap();
    assert!(url.starts_with(&format!("{}/authorize?", mock.issuer)));
    assert_eq!(query_param(&url, "code_challenge_method"), "S256");
    assert_eq!(query_param(&url, "redirect_uri"), REDIRECT);
    assert!(query_param(&url, "scope").contains("openid"));
    let state = query_param(&url, "state");
    {
        let mut expected = mock.expected.lock().unwrap();
        expected.challenge = query_param(&url, "code_challenge");
        expected.nonce = query_param(&url, "nonce");
    }

    // A wrong state is refused before anything is sent to the provider.
    let (_, other) = flow::start(&config, REDIRECT).await.unwrap();
    assert!(matches!(
        flow::finish(&config, REDIRECT, other, "the-code", &state).await,
        Err(FlowError::BadState)
    ));

    let identity = flow::finish(&config, REDIRECT, pending, "the-code", &state)
        .await
        .unwrap();
    assert_eq!(identity.subject, "subject-1");
    assert_eq!(identity.email.as_deref(), Some("jane@example.org"));
    assert!(identity.email_verified);
    assert_eq!(identity.first_name.as_deref(), Some("Jane"));

    // A token signed with an unpublished key is refused.
    let (url, pending) = flow::start(&config, REDIRECT).await.unwrap();
    {
        let mut expected = mock.expected.lock().unwrap();
        expected.challenge = query_param(&url, "code_challenge");
        expected.nonce = query_param(&url, "nonce");
        expected.forge = true;
    }
    let state = query_param(&url, "state");
    assert!(matches!(
        flow::finish(&config, REDIRECT, pending, "the-code", &state).await,
        Err(FlowError::Token(_))
    ));

    // A token for another sign-in attempt (wrong nonce) is refused.
    let (url, pending) = flow::start(&config, REDIRECT).await.unwrap();
    {
        let mut expected = mock.expected.lock().unwrap();
        expected.challenge = query_param(&url, "code_challenge");
        expected.nonce = "someone-elses-nonce".into();
        expected.forge = false;
    }
    let state = query_param(&url, "state");
    assert!(matches!(
        flow::finish(&config, REDIRECT, pending, "the-code", &state).await,
        Err(FlowError::Token(_))
    ));

    // A stolen code without the PKCE verifier is refused by the provider.
    let (url, mut pending) = flow::start(&config, REDIRECT).await.unwrap();
    mock.expected.lock().unwrap().challenge = query_param(&url, "code_challenge");
    pending.verifier = "x".repeat(64);
    let state = query_param(&url, "state");
    assert!(matches!(
        flow::finish(&config, REDIRECT, pending, "the-code", &state).await,
        Err(FlowError::Exchange(_))
    ));
}

#[test]
fn usernames_from_identities() {
    assert_eq!(
        username_base("Jane.Doe@example.org").as_deref(),
        Some("jane.doe")
    );
    assert_eq!(username_base("__x y!").as_deref(), Some("x_y"));
    assert_eq!(username_base("@example.org"), None);
}

fn identity(subject: &str, email: &str, verified: bool) -> Identity {
    Identity {
        subject: subject.into(),
        email: Some(email.into()),
        email_verified: verified,
        first_name: Some("Jane".into()),
        last_name: Some("Doe".into()),
        preferred_username: Some(email.into()),
        phone: None,
    }
}

#[sqlx::test]
async fn test_account_linking(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    xguard_common::db::models::settings::initialize_current_settings(&pool)
        .await
        .unwrap();
    let set_create = |create: bool| {
        let pool = pool.clone();
        async move {
            let mut settings = Settings::get_current_settings();
            settings.openid_create_account = create;
            update_current_settings(&pool, settings).await.unwrap();
        }
    };
    let existing = User::new(
        "jdoe",
        Some("Pass123!"),
        "Doe",
        "Jane",
        "jane@example.org",
        None,
    )
    .save(&pool)
    .await
    .unwrap();

    // An unverified email never links to an existing account.
    assert!(matches!(
        resolve_user(&pool, &identity("s1", "jane@example.org", false)).await,
        Err(LinkError::UnverifiedEmail)
    ));
    // A verified one links it, and the subject is remembered.
    let linked = resolve_user(&pool, &identity("s1", "JANE@example.org", true))
        .await
        .unwrap();
    assert_eq!(linked.id, existing.id);
    assert_eq!(linked.openid_sub.as_deref(), Some("s1"));
    // The subject then finds it even if the email changed at the provider.
    let again = resolve_user(&pool, &identity("s1", "new@example.org", false))
        .await
        .unwrap();
    assert_eq!(again.id, existing.id);
    // Another identity with the same email cannot take it over.
    assert!(matches!(
        resolve_user(&pool, &identity("s2", "jane@example.org", true)).await,
        Err(LinkError::LinkedElsewhere)
    ));

    // Unknown people get an account only when that is allowed, and only with a verified email.
    set_create(false).await;
    assert!(matches!(
        resolve_user(&pool, &identity("s3", "bob@example.org", true)).await,
        Err(LinkError::NoAccount)
    ));
    set_create(true).await;
    assert!(matches!(
        resolve_user(&pool, &identity("s3", "bob@example.org", false)).await,
        Err(LinkError::UnverifiedEmail)
    ));
    let created = resolve_user(&pool, &identity("s3", "jdoe@example.org", true))
        .await
        .unwrap();
    // "jdoe" is taken, so a suffix is added; no password is set.
    assert_eq!(created.username, "jdoe-1");
    assert!(!created.has_password());
    assert_eq!(created.openid_sub.as_deref(), Some("s3"));
}

#[sqlx::test]
async fn test_provider_settings(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let input = |issuer: &str, secret: Option<&str>| ProviderInput {
        kind: ProviderKind::Google,
        issuer: issuer.into(),
        client_id: "client".into(),
        client_secret: secret.map(str::to_owned),
        enabled: true,
        display_name: Some("Google".into()),
        disable_password_management: false,
        directory_sync: Default::default(),
    };
    let mut conn = pool.acquire().await.unwrap();
    // Plain HTTP is only accepted for a provider on this machine; a secret is required.
    assert!(
        ProviderConfig::save(&mut conn, input("http://idp.example.org", Some("s")))
            .await
            .is_err()
    );
    assert!(
        ProviderConfig::save(&mut conn, input("https://accounts.google.com", None))
            .await
            .is_err()
    );
    let saved = ProviderConfig::save(&mut conn, input("https://accounts.google.com/", Some("s")))
        .await
        .unwrap();
    assert_eq!(saved.issuer, "https://accounts.google.com");
    assert!(saved.client_secret_set);
    assert!(!serde_json::to_string(&saved).unwrap().contains("\"s\""));

    // Saving without a secret keeps it; changing the issuer unlinks accounts.
    let user = User::new("jdoe", None, "Doe", "Jane", "jane@example.org", None)
        .save(&pool)
        .await
        .unwrap();
    sqlx::query(r#"UPDATE "user" SET openid_sub = 'g-1' WHERE id = $1"#)
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
    ProviderConfig::save(&mut conn, input("https://accounts.google.com", None))
        .await
        .unwrap();
    let kept = ProviderConfig::current(&pool).await.unwrap().unwrap();
    assert_eq!(kept.client_secret, "s");
    assert!(
        User::find_by_id(&pool, user.id)
            .await
            .unwrap()
            .unwrap()
            .openid_sub
            .is_some()
    );
    ProviderConfig::save(&mut conn, input("https://login.example.org", None))
        .await
        .unwrap();
    assert!(
        User::find_by_id(&pool, user.id)
            .await
            .unwrap()
            .unwrap()
            .openid_sub
            .is_none()
    );

    ProviderConfig::delete(&pool).await.unwrap();
    assert!(ProviderConfig::current(&pool).await.unwrap().is_none());
}
