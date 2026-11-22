//! Secure remote enrollment of directory users against a real OpenLDAP server: invitations for
//! users a sync adds, the directory password check for the enrollment portal, and enrollment
//! tokens stored in (and removed from) a directory attribute through the admin API.
//!
//! Runs only when `XGUARD_TEST_LDAP_URL` is set, like `directory.rs`; settings are global, so
//! run it on its own: `cargo test -p xguard_core --test integration directory_enrollment --
//! --test-threads=1`.

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::mpsc::unbounded_channel;
use xguard_common::{
    db::{
        models::{
            Settings, User,
            settings::{initialize_current_settings, update_current_settings},
        },
        setup_pool,
    },
    testing::smtp::MockSmtpServer,
};
use xguard_core::{
    db::models::enrollment::Token,
    directory::{
        self, DirectoryClient, SyncOptions,
        enrollment::{EnrollmentError, authenticate, clear_token},
    },
    events::{ApiEventType, LdapSyncEventType},
    handlers::Auth,
};

use crate::{
    api::make_test_client,
    directory::{attributes, cleanup, configure, ldap_url},
};

const TOKEN_ATTR: &str = "description";

async fn read_token_attribute(client: &mut DirectoryClient, username: &str) -> Vec<String> {
    let entry = client.find_user(username).await.unwrap().unwrap();
    client.read_attribute(&entry.dn, TOKEN_ATTR).await.unwrap()
}

#[sqlx::test]
async fn test_directory_remote_enrollment(_: PgPoolOptions, options: PgConnectOptions) {
    let Some(url) = ldap_url() else {
        eprintln!("XGUARD_TEST_LDAP_URL is not set; skipping the directory enrollment test");
        return;
    };
    let pool = setup_pool(options).await;
    let (mut client, _state) = make_test_client(pool.clone()).await;
    let smtp = MockSmtpServer::start().await;
    smtp.configure(&pool).await;

    let config = configure(&pool, &url, true, "de_vpn").await;
    let mut settings = Settings::get_current_settings();
    settings.ldap_remote_enrollment_enabled = true;
    settings.ldap_remote_enrollment_send_invite = true;
    settings.ldap_enrollment_token_attr = Some(TOKEN_ATTR.into());
    settings.public_proxy_url = "https://edge.example.org/".into();
    update_current_settings(&pool, settings).await.unwrap();

    let mut ldap = DirectoryClient::connect(config.clone()).await.unwrap();
    cleanup(&mut ldap, &["de_ann", "de_ben"], &["de_vpn"]).await;
    let ann_dn = ldap
        .add_user(&attributes("de_ann"), None, Some("AnnSecret123!"))
        .await
        .unwrap();
    let ben_dn = ldap
        .add_user(&attributes("de_ben"), None, Some("BenSecret123!"))
        .await
        .unwrap();
    let group_dn = ldap.create_group("de_vpn", &ann_dn).await.unwrap();
    ldap.add_member(&group_dn, &ben_dn).await.unwrap();

    // --- A sync adds both users and invites them by mail. ---
    let (events, mut events_rx) = unbounded_channel();
    let (gateway_tx, _gateway_rx) = unbounded_channel();
    let report = directory::sync::run(
        &pool,
        config.clone(),
        SyncOptions::default(),
        &events,
        &gateway_tx,
    )
    .await
    .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let mut invited = Vec::new();
    while invited.len() < 2 {
        let event = tokio::time::timeout(Duration::from_secs(10), events_rx.recv())
            .await
            .expect("no invitation event")
            .unwrap();
        if let LdapSyncEventType::EnrollmentInviteSent { user } = event {
            invited.push(user.username);
        }
    }
    invited.sort();
    assert_eq!(invited, ["de_ann", "de_ben"]);
    let received = smtp.wait_for_count(2).await;
    let mut recipients: Vec<String> = received
        .iter()
        .flat_map(|mail| mail.recipients.clone())
        .collect();
    recipients.sort();
    assert_eq!(recipients, ["de_ann@example.org", "de_ben@example.org"]);

    let ann = User::find_by_username(&pool, "de_ann")
        .await
        .unwrap()
        .unwrap();
    assert!(ann.from_ldap);
    assert!(!ann.is_enrolled(), "directory users enroll remotely first");
    let tokens = Token::fetch_all(&pool).await.unwrap();
    let ann_invite = tokens
        .iter()
        .find(|token| token.user_id == ann.id)
        .expect("invitation token for de_ann");

    // --- The enrollment portal checks the directory password. ---
    let mut known = None;
    assert!(matches!(
        authenticate(&pool, "de_ann", "wrong-password", &mut known).await,
        Err(EnrollmentError::Rejected)
    ));
    assert_eq!(known.as_ref().map(|user| user.id), Some(ann.id));
    assert!(matches!(
        authenticate(&pool, "de_ann", "", &mut known).await,
        Err(EnrollmentError::Rejected)
    ));
    let authenticated = authenticate(&pool, "de_ann", "AnnSecret123!", &mut known)
        .await
        .expect("directory password accepted");
    assert_eq!(authenticated.user.id, ann.id);
    // Email works as the login name too.
    let authenticated = authenticate(&pool, "de_ann@example.org", "AnnSecret123!", &mut None)
        .await
        .expect("email accepted");
    assert_eq!(authenticated.user.id, ann.id);

    // --- An admin stores enrollment tokens in the directory. ---
    let response = client
        .post("/api/v1/auth")
        .json(&Auth::new("admin", "pass123"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let ben = User::find_by_username(&pool, "de_ben")
        .await
        .unwrap()
        .unwrap();
    let admin = User::find_by_username(&pool, "admin")
        .await
        .unwrap()
        .unwrap();
    let hpotter = User::find_by_username(&pool, "hpotter")
        .await
        .unwrap()
        .unwrap();
    client.drain_all_events();

    // Your own account is refused.
    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [ann.id, admin.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A local account without a directory entry is skipped.
    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [ann.id, ben.id, hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await;
    assert_eq!(body, json!({ "stored": 2, "skipped": 1, "failed": 0 }));

    let stored = read_token_attribute(&mut ldap, "de_ann").await;
    assert_eq!(stored.len(), 1);
    let value: Value = serde_json::from_str(&stored[0]).unwrap();
    assert_eq!(value["enrollmentUrl"], "https://edge.example.org/");
    let token = value["enrollmentToken"].as_str().unwrap();
    let token = Token::find_by_id(&pool, token).await.expect("valid token");
    assert_eq!(token.user_id, ann.id);
    assert!(
        Token::find_by_id(&pool, &ann_invite.id).await.is_err(),
        "the new token replaces the unused invitation"
    );

    let events = client.drain_all_events();
    let mut stored_for: Vec<String> = events
        .iter()
        .filter_map(|(event, _, _)| match event {
            ApiEventType::EnrollmentTokenStoredInDirectory { user, attribute } => {
                assert_eq!(attribute, TOKEN_ATTR);
                Some(user.username.clone())
            }
            _ => None,
        })
        .collect();
    stored_for.sort();
    assert_eq!(stored_for, ["de_ann", "de_ben"]);

    // --- Finishing enrollment removes the stored token. ---
    clear_token("de_ann").await.unwrap();
    assert!(read_token_attribute(&mut ldap, "de_ann").await.is_empty());
    assert_eq!(read_token_attribute(&mut ldap, "de_ben").await.len(), 1);
    // Removing it again is harmless.
    clear_token("de_ann").await.unwrap();

    // --- Enrolled users cannot use the portal sign-in again. ---
    let mut ann = User::find_by_username(&pool, "de_ann")
        .await
        .unwrap()
        .unwrap();
    ann.enrollment_pending = false;
    ann.ldap_remote_enrollment_completed = true;
    ann.save(&pool).await.unwrap();
    assert!(matches!(
        authenticate(&pool, "de_ann", "AnnSecret123!", &mut None).await,
        Err(EnrollmentError::AlreadyEnrolled)
    ));

    // --- Unsafe attributes are refused even if the settings row holds one. ---
    sqlx::query("UPDATE settings SET ldap_enrollment_token_attr = 'userPassword'")
        .execute(&pool)
        .await
        .unwrap();
    initialize_current_settings(&pool).await.unwrap();
    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [ben.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // --- Turning the feature off closes the portal sign-in. ---
    let mut settings = Settings::get_current_settings();
    settings.ldap_enrollment_token_attr = Some(TOKEN_ATTR.into());
    settings.ldap_remote_enrollment_enabled = false;
    update_current_settings(&pool, settings).await.unwrap();
    assert!(matches!(
        authenticate(&pool, "de_ben", "BenSecret123!", &mut None).await,
        Err(EnrollmentError::Disabled)
    ));

    cleanup(&mut ldap, &["de_ann", "de_ben"], &["de_vpn"]).await;
    ldap.close().await;
}

/// The bulk action is refused while the integration or the attribute is not set up, before any
/// token is created.
#[sqlx::test]
async fn test_store_enrollment_tokens_requires_configuration(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client(pool.clone()).await;
    let response = client
        .post("/api/v1/auth")
        .json(&Auth::new("admin", "pass123"))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let hpotter = User::find_by_username(&pool, "hpotter")
        .await
        .unwrap()
        .unwrap();

    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await;
    assert!(body["msg"].as_str().unwrap().contains("not configured"));

    let mut settings = Settings::get_current_settings();
    settings.ldap_enrollment_token_attr = Some(TOKEN_ATTR.into());
    settings.ldap_enabled = false;
    update_current_settings(&pool, settings).await.unwrap();
    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await;
    assert!(body["msg"].as_str().unwrap().contains("not enabled"));
    assert!(Token::fetch_all(&pool).await.unwrap().is_empty());

    // Not for regular users.
    let mut client = client;
    client.drain_all_events();
    client.login_user("hpotter", "pass123").await;
    let response = client
        .post("/api/v1/user/bulk-store-enrollment-token-ldap")
        .json(&json!({ "users": [hpotter.id] }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
