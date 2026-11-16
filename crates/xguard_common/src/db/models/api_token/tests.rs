use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeDelta, Utc};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use super::{
    ApiToken, ApiTokenError, MAX_NAME_LEN, MAX_TOKENS_PER_USER, NewApiToken, TOKEN_LEN,
    TOKEN_PREFIX, hash_token, validate_name,
};
use crate::db::{Id, models::User, setup_pool};

fn new_token(name: &str) -> NewApiToken {
    NewApiToken {
        name: name.into(),
        expires_in_days: None,
        read_only: false,
    }
}

async fn user(pool: &PgPool, name: &str) -> User<Id> {
    let email = format!("{name}@xguard.local");
    User::new(name, None, "Test", name, email.as_str(), None)
        .save(pool)
        .await
        .unwrap()
}

async fn create(pool: &PgPool, user_id: Id, input: &NewApiToken) -> (ApiToken, String) {
    let mut transaction = pool.begin().await.unwrap();
    let created = ApiToken::create(&mut transaction, user_id, input)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    created
}

#[test]
fn token_format_and_hashing() {
    let token = super::generate();
    assert_eq!(token.len(), TOKEN_LEN);
    assert!(token.starts_with(TOKEN_PREFIX));
    assert_ne!(token, super::generate());

    let hash = hash_token(&token).unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(hash_token(&token), Some(hash));

    for bad in [
        String::new(),
        "xgt_".into(),
        token[..TOKEN_LEN - 1].to_string(),
        format!("{token}A"),
        token.replacen(TOKEN_PREFIX, "dgt_", 1),
        format!("{}+{}", &token[..10], &token[11..]),
        format!("{}é{}", &token[..10], &token[12..]),
    ] {
        assert_eq!(hash_token(&bad), None, "{bad}");
    }
}

#[test]
fn name_validation() {
    assert_eq!(validate_name("  deploy bot ").unwrap(), "deploy bot");
    assert!(validate_name("").is_err());
    assert!(validate_name("   ").is_err());
    assert!(validate_name("line\nbreak").is_err());
    assert!(validate_name("<img src=x>").is_err());
    assert!(validate_name("Deploy bot (prod)").is_ok());
    assert!(validate_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
    assert!(validate_name(&"é".repeat(MAX_NAME_LEN + 1)).is_err());
}

#[sqlx::test]
async fn test_create_authenticate_and_revoke(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;

    let (token, secret) = create(
        &pool,
        alice.id,
        &NewApiToken {
            expires_in_days: Some(30),
            read_only: true,
            ..new_token(" ci ")
        },
    )
    .await;
    assert_eq!(token.name, "ci");
    assert!(token.read_only);
    assert_eq!(token.hint, secret[..TOKEN_PREFIX.len() + 4]);
    let expires_at = token.expires_at.unwrap();
    assert!(expires_at > Utc::now().naive_utc() + TimeDelta::days(29));

    // The secret is not stored.
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM api_token WHERE id = $1")
        .bind(token.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, secret);
    assert!(!stored.contains(&secret[TOKEN_PREFIX.len()..]));

    let auth = ApiToken::authenticate(&pool, &secret)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (auth.id, auth.user_id, auth.read_only),
        (token.id, alice.id, true)
    );
    assert!(
        ApiToken::authenticate(&pool, "xgt_nope")
            .await
            .unwrap()
            .is_none()
    );
    let unknown = super::generate();
    assert!(
        ApiToken::authenticate(&pool, &unknown)
            .await
            .unwrap()
            .is_none()
    );

    // Last use is recorded, then throttled.
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    ApiToken::record_use(&pool, &auth, ip).await.unwrap();
    let used = ApiToken::find_for_user(&pool, token.id, alice.id)
        .await
        .unwrap()
        .unwrap();
    let first_use = used.last_used_at.unwrap();
    assert_eq!(used.last_used_ip.unwrap().ip(), ip);
    let auth = ApiToken::authenticate(&pool, &secret)
        .await
        .unwrap()
        .unwrap();
    ApiToken::record_use(&pool, &auth, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await
        .unwrap();
    let used = ApiToken::find_for_user(&pool, token.id, alice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(used.last_used_at, Some(first_use));
    assert_eq!(used.last_used_ip.unwrap().ip(), ip);

    // Tokens are scoped to their owner.
    assert!(
        ApiToken::find_for_user(&pool, token.id, bob.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        ApiToken::rename(&pool, token.id, bob.id, "stolen").await,
        Err(ApiTokenError::NotFound)
    ));
    assert!(
        ApiToken::delete(&pool, token.id, bob.id)
            .await
            .unwrap()
            .is_none()
    );

    let renamed = ApiToken::rename(&pool, token.id, alice.id, "ci-main")
        .await
        .unwrap();
    assert_eq!(renamed.name, "ci-main");

    let (_, other) = create(&pool, alice.id, &new_token("other")).await;
    assert_eq!(
        ApiToken::find_by_user(&pool, alice.id).await.unwrap().len(),
        2
    );
    assert_eq!(
        ApiToken::delete_all_for_user(&pool, alice.id)
            .await
            .unwrap(),
        2
    );
    assert!(
        ApiToken::authenticate(&pool, &secret)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ApiToken::authenticate(&pool, &other)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn test_create_limits(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let alice = user(&pool, "alice").await;

    let mut conn = pool.acquire().await.unwrap();
    for days in [0, super::MAX_LIFETIME_DAYS + 1] {
        let result = ApiToken::create(
            &mut conn,
            alice.id,
            &NewApiToken {
                expires_in_days: Some(days),
                ..new_token("bad")
            },
        )
        .await;
        assert!(matches!(result, Err(ApiTokenError::Invalid(_))), "{days}");
    }
    assert!(matches!(
        ApiToken::create(&mut conn, alice.id, &new_token(" ")).await,
        Err(ApiTokenError::Invalid(_))
    ));

    for i in 0..MAX_TOKENS_PER_USER {
        ApiToken::create(&mut conn, alice.id, &new_token(&format!("t{i}")))
            .await
            .unwrap();
    }
    assert!(matches!(
        ApiToken::create(&mut conn, alice.id, &new_token("one too many")).await,
        Err(ApiTokenError::TooMany)
    ));
}

#[sqlx::test]
async fn test_expired_tokens(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let alice = user(&pool, "alice").await;
    let (token, secret) = create(
        &pool,
        alice.id,
        &NewApiToken {
            expires_in_days: Some(1),
            ..new_token("short")
        },
    )
    .await;
    assert!(!token.is_expired());

    sqlx::query("UPDATE api_token SET expires_at = $2 WHERE id = $1")
        .bind(token.id)
        .bind(Utc::now().naive_utc() - TimeDelta::seconds(1))
        .execute(&pool)
        .await
        .unwrap();
    let auth = ApiToken::authenticate(&pool, &secret)
        .await
        .unwrap()
        .unwrap();
    assert!(auth.is_expired(Utc::now().naive_utc()));
    let stored = ApiToken::find_for_user(&pool, token.id, alice.id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.is_expired());
}
