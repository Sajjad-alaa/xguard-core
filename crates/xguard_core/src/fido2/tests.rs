//! Server-side FIDO2 ceremonies against the software authenticator.

use chrono::{TimeDelta, Utc};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use xguard_common::db::{
    Id,
    models::{
        Settings, User,
        settings::initialize_current_settings,
        webauthn::{AuthenticatorInfo, RegistrationSource, WebAuthn},
    },
    setup_pool,
};

use super::{
    CHALLENGE_TTL, ClientDataType, Fido2Error, client_data_json, finish_registration,
    issue_challenge, start_registration, test_authenticator::TestAuthenticator, validate_key_name,
    verify_assertion,
};

// The default XGuard URL of a fresh database: settings are process-wide, so tests running in
// parallel keep agreeing on the relying party.
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8000";

async fn setup(options: PgConnectOptions) -> PgPool {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool)
        .await
        .expect("failed to init settings");
    assert_eq!(
        Settings::get_current_settings()
            .xguard_url
            .trim_end_matches('/'),
        ORIGIN
    );
    pool
}

async fn create_user(pool: &PgPool, username: &str) -> User<Id> {
    User::new(
        username,
        Some("pass123"),
        "Key",
        "Holder",
        &format!("{username}@example.com"),
        None,
    )
    .save(pool)
    .await
    .expect("failed to create user")
}

/// Registers `authenticator` for `user` and enables it for VPN MFA, as the setup flow does.
async fn register(pool: &PgPool, user: &User<Id>, authenticator: &mut TestAuthenticator) -> Id {
    let (options, state) = start_registration(pool, user)
        .await
        .expect("registration must start");
    let response = authenticator.register(&options, ORIGIN);
    let passkey = finish_registration(&state, &response).expect("registration must finish");
    let key = WebAuthn::new(
        user.id,
        "test key".to_owned(),
        &passkey,
        AuthenticatorInfo::unattested(RegistrationSource::Desktop),
    )
    .expect("key")
    .save(pool)
    .await
    .expect("failed to save the key");
    key.enable_vpn_mfa(pool)
        .await
        .expect("failed to enable the key");
    key.id
}

#[test]
fn client_data_is_canonical() {
    // The desktop client has the same vector; both sides must agree byte for byte.
    assert_eq!(
        client_data_json(
            ClientDataType::Get,
            "q83vEjRWeJA",
            "https://xguard.example.com"
        ),
        br#"{"type":"webauthn.get","challenge":"q83vEjRWeJA","origin":"https://xguard.example.com","crossOrigin":false}"#
    );
    assert_eq!(
        client_data_json(ClientDataType::Create, "a\"b", "https://h:8443"),
        br#"{"type":"webauthn.create","challenge":"a\"b","origin":"https://h:8443","crossOrigin":false}"#
    );
}

#[test]
fn key_names_are_validated() {
    assert_eq!(validate_key_name("  YubiKey 5 ").unwrap(), "YubiKey 5");
    assert!(validate_key_name("   ").is_err());
    assert!(validate_key_name("a\nb").is_err());
    assert!(validate_key_name(&"k".repeat(65)).is_err());
    assert!(validate_key_name(&"ł".repeat(64)).is_ok());
}

#[sqlx::test]
async fn test_assertion_is_verified_and_counter_recorded(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    let key_id = register(&pool, &user, &mut authenticator).await;

    let issued = issue_challenge(&pool, user.id).await.expect("challenge");
    assert_eq!(
        issued.credential_ids,
        vec![base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &authenticator.credential_id
        )]
    );
    assert_eq!(issued.challenge, issued.state.challenge);
    let assertion = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    let key = verify_assertion(&pool, user.id, &issued.state, &assertion)
        .await
        .expect("a valid assertion must verify");
    assert_eq!(key.id, key_id);
    assert_eq!(key.name, "test key");

    let stored = WebAuthn::vpn_keys_for_user(&pool, user.id).await.unwrap();
    let counter = serde_json::to_value(&stored[0].passkey).unwrap()["cred"]["counter"].clone();
    assert_eq!(
        counter,
        serde_json::json!(1),
        "the new counter must be stored"
    );
    let last_used: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT last_used_at FROM webauthn_vpn_mfa WHERE webauthn_id = $1")
            .bind(key_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(last_used.is_some());

    // A second sign-in with a higher counter works.
    let issued = issue_challenge(&pool, user.id).await.unwrap();
    let assertion = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    verify_assertion(&pool, user.id, &issued.state, &assertion)
        .await
        .expect("a second sign-in must verify");
}

#[sqlx::test]
async fn test_counter_that_does_not_increase_is_refused(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    register(&pool, &user, &mut authenticator).await;

    let issued = issue_challenge(&pool, user.id).await.unwrap();
    let assertion = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    verify_assertion(&pool, user.id, &issued.state, &assertion)
        .await
        .unwrap();

    // A clone of the key still at counter 1 signs a fresh challenge.
    let issued = issue_challenge(&pool, user.id).await.unwrap();
    let client_data = client_data_json(ClientDataType::Get, &issued.challenge, ORIGIN);
    let assertion = authenticator.assert_client_data_with_counter(RP_ID, &client_data, 1);
    let err = verify_assertion(&pool, user.id, &issued.state, &assertion)
        .await
        .expect_err("a repeated counter must be refused");
    assert!(
        matches!(err, Fido2Error::Rejected(message) if message.contains("cloned")),
        "{err:?}"
    );
}

#[sqlx::test]
async fn test_assertion_bound_to_challenge_origin_and_rp(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    register(&pool, &user, &mut authenticator).await;

    let first = issue_challenge(&pool, user.id).await.unwrap();
    let second = issue_challenge(&pool, user.id).await.unwrap();
    assert_ne!(first.challenge, second.challenge);

    let cases = [
        // Signed for another attempt's challenge.
        authenticator.assert(RP_ID, &first.challenge, ORIGIN),
        // Signed for another origin.
        authenticator.assert(RP_ID, &second.challenge, "https://evil.example.com"),
        // Signed for another relying party.
        authenticator.assert("evil.example.com", &second.challenge, ORIGIN),
    ];
    for assertion in cases {
        let err = verify_assertion(&pool, user.id, &second.state, &assertion)
            .await
            .expect_err("must be refused");
        assert!(matches!(err, Fido2Error::Rejected(_)), "{err:?}");
    }

    // A tampered signature.
    let mut assertion = authenticator.assert(RP_ID, &second.challenge, ORIGIN);
    let last = assertion.signature.len() - 1;
    assertion.signature[last] ^= 1;
    assert!(matches!(
        verify_assertion(&pool, user.id, &second.state, &assertion).await,
        Err(Fido2Error::Rejected(_))
    ));
}

#[sqlx::test]
async fn test_user_verification_is_required(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    register(&pool, &user, &mut authenticator).await;

    authenticator.user_verified = false;
    let issued = issue_challenge(&pool, user.id).await.unwrap();
    let assertion = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    assert!(matches!(
        verify_assertion(&pool, user.id, &issued.state, &assertion).await,
        Err(Fido2Error::Rejected(_))
    ));

    // Registration without a PIN is refused too.
    let mut no_pin = TestAuthenticator::new();
    no_pin.user_verified = false;
    let (options, state) = start_registration(&pool, &user).await.unwrap();
    let response = no_pin.register(&options, ORIGIN);
    assert!(matches!(
        finish_registration(&state, &response),
        Err(Fido2Error::Rejected(_))
    ));
}

#[sqlx::test]
async fn test_only_own_vpn_keys_count(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let other = create_user(&pool, "someone").await;
    let mut own = TestAuthenticator::new();
    register(&pool, &user, &mut own).await;
    let mut foreign = TestAuthenticator::new();
    register(&pool, &other, &mut foreign).await;

    // The other user's key, valid for its owner, does not answer this user's challenge.
    let issued = issue_challenge(&pool, user.id).await.unwrap();
    assert_eq!(issued.credential_ids.len(), 1);
    let assertion = foreign.assert(RP_ID, &issued.challenge, ORIGIN);
    let err = verify_assertion(&pool, user.id, &issued.state, &assertion)
        .await
        .expect_err("a foreign key must be refused");
    assert!(matches!(err, Fido2Error::Rejected(_)), "{err:?}");

    // A web sign-in key not enabled for VPN MFA is not offered.
    let web_only = create_user(&pool, "webonly").await;
    let mut web_key = TestAuthenticator::new();
    let (options, state) = start_registration(&pool, &web_only).await.unwrap();
    let passkey = finish_registration(&state, &web_key.register(&options, ORIGIN)).unwrap();
    WebAuthn::new(
        web_only.id,
        "web".to_owned(),
        &passkey,
        AuthenticatorInfo::unattested(RegistrationSource::Core),
    )
    .unwrap()
    .save(&pool)
    .await
    .unwrap();
    assert!(matches!(
        issue_challenge(&pool, web_only.id).await,
        Err(Fido2Error::NotConfigured)
    ));

    // A key removed after the challenge was issued no longer answers it.
    let issued = issue_challenge(&pool, user.id).await.unwrap();
    WebAuthn::delete_all_for_user(&pool, user.id).await.unwrap();
    let assertion = own.assert(RP_ID, &issued.challenge, ORIGIN);
    assert!(matches!(
        verify_assertion(&pool, user.id, &issued.state, &assertion).await,
        Err(Fido2Error::Rejected(_))
    ));
}

#[sqlx::test]
async fn test_expired_challenge_is_refused(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    register(&pool, &user, &mut authenticator).await;

    let mut issued = issue_challenge(&pool, user.id).await.unwrap();
    issued.state.issued_at = Utc::now().naive_utc()
        - TimeDelta::from_std(CHALLENGE_TTL).unwrap()
        - TimeDelta::seconds(1);
    let assertion = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    assert!(matches!(
        verify_assertion(&pool, user.id, &issued.state, &assertion).await,
        Err(Fido2Error::Expired)
    ));
}

#[sqlx::test]
async fn test_malformed_assertions_are_refused_before_crypto(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;
    let mut authenticator = TestAuthenticator::new();
    register(&pool, &user, &mut authenticator).await;
    let issued = issue_challenge(&pool, user.id).await.unwrap();

    let valid = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    let mut cases = Vec::new();
    let mut case = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    case.rp_id_hash = vec![0; 32];
    cases.push(case);
    let mut case = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    case.authenticator_data.truncate(20);
    cases.push(case);
    let mut case = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    case.credential_id = vec![1; 2000];
    cases.push(case);
    let mut case = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    case.signature = vec![0; 4096];
    cases.push(case);
    let mut case = authenticator.assert(RP_ID, &issued.challenge, ORIGIN);
    case.signature.clear();
    cases.push(case);
    for case in cases {
        assert!(matches!(
            verify_assertion(&pool, user.id, &issued.state, &case).await,
            Err(Fido2Error::Malformed(_))
        ));
    }
    // An empty RP ID hash is allowed: authenticator data carries it.
    let mut case = valid;
    case.rp_id_hash.clear();
    assert!(
        verify_assertion(&pool, user.id, &issued.state, &case)
            .await
            .is_ok()
    );
}

#[sqlx::test]
async fn test_registration_refuses_synced_and_duplicate_keys(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup(options).await;
    let user = create_user(&pool, "keyholder").await;

    let mut synced = TestAuthenticator::new();
    synced.backup_eligible = true;
    let (options, state) = start_registration(&pool, &user).await.unwrap();
    let err = finish_registration(&state, &synced.register(&options, ORIGIN))
        .expect_err("a synced passkey must be refused");
    assert!(matches!(err, Fido2Error::Rejected(_)), "{err:?}");

    // Another ceremony's state does not finish this one.
    let mut key = TestAuthenticator::new();
    let (options, _) = start_registration(&pool, &user).await.unwrap();
    let (_, other_state) = start_registration(&pool, &user).await.unwrap();
    assert!(matches!(
        finish_registration(&other_state, &key.register(&options, ORIGIN)),
        Err(Fido2Error::Rejected(_))
    ));

    // A registered key is excluded from later registrations.
    register(&pool, &user, &mut key).await;
    let (options, _) = start_registration(&pool, &user).await.unwrap();
    let options: serde_json::Value = serde_json::from_str(&options).unwrap();
    assert_eq!(
        options["publicKey"]["excludeCredentials"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );

    assert!(matches!(
        finish_registration(b"not cbor", "{}"),
        Err(Fido2Error::Malformed(_))
    ));
    assert!(matches!(
        finish_registration(&[], &"x".repeat(super::MAX_ATTESTATION_LEN + 1)),
        Err(Fido2Error::Malformed(_))
    ));
}
