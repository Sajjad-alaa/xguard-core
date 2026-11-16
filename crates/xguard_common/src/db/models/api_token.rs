//! Personal API tokens for automation, sent as `Authorization: Bearer xgt_…`.
//!
//! - A token is `xgt_` followed by 32 random bytes from the OS, base64url-encoded. The fixed
//!   prefix lets secret scanners recognise leaked tokens.
//! - Only a SHA-256 of the whole token is stored. The token has 256 bits of entropy, so a slow
//!   password hash would add cost without adding security. The token is shown once, at creation.
//! - Malformed values are rejected before the database is queried.
//! - A token can expire and can be limited to read-only requests. The time and address of its
//!   last use are recorded at most once a minute, so busy scripts do not write on every request.

use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{NaiveDateTime, TimeDelta, Utc};
use ipnetwork::IpNetwork;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgExecutor};

use crate::db::Id;

/// Every XGuard API token starts with this.
pub const TOKEN_PREFIX: &str = "xgt_";
const SECRET_BYTES: usize = 32;
/// `xgt_` plus the unpadded base64url encoding of [`SECRET_BYTES`].
const TOKEN_LEN: usize = TOKEN_PREFIX.len() + (SECRET_BYTES * 4).div_ceil(3);
/// How many characters of the secret are kept, so people can tell their tokens apart.
const HINT_LEN: usize = 4;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_TOKENS_PER_USER: i64 = 25;
pub const MAX_LIFETIME_DAYS: u32 = 366;
/// Last-use information is refreshed at most this often.
const LAST_USED_RESOLUTION: TimeDelta = TimeDelta::seconds(60);

#[derive(Clone, Debug, Serialize, PartialEq, Eq, FromRow)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiToken {
    pub id: Id,
    pub user_id: Id,
    pub name: String,
    /// The start of the token, such as `xgt_AbCd`, for telling tokens apart.
    pub hint: String,
    pub created_at: NaiveDateTime,
    /// The token stops working at this time. `None` means it never expires.
    pub expires_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(serialize_with = "serialize_ip")]
    pub last_used_ip: Option<IpNetwork>,
    /// A read-only token can only make GET, HEAD and OPTIONS requests.
    pub read_only: bool,
}

fn serialize_ip<S: serde::Serializer>(ip: &Option<IpNetwork>, s: S) -> Result<S::Ok, S::Error> {
    match ip {
        Some(ip) => s.serialize_some(&ip.ip().to_string()),
        None => s.serialize_none(),
    }
}

impl ApiToken {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now().naive_utc())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NewApiToken {
    pub name: String,
    /// Days until the token expires, from 1 to 366. Leave it out for a token that never expires.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiTokenError {
    #[error("{0}")]
    Invalid(String),
    #[error("API token not found")]
    NotFound,
    #[error("A user can have at most {MAX_TOKENS_PER_USER} API tokens.")]
    TooMany,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// The details needed to authenticate a request.
#[derive(Clone, Debug, FromRow)]
pub struct TokenAuth {
    pub id: Id,
    pub user_id: Id,
    pub read_only: bool,
    pub expires_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
}

impl TokenAuth {
    #[must_use]
    pub fn is_expired(&self, now: NaiveDateTime) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn last_use_is_stale(&self, now: NaiveDateTime) -> bool {
        self.last_used_at
            .is_none_or(|last_used_at| now - last_used_at >= LAST_USED_RESOLUTION)
    }
}

/// Checks and trims a token name.
pub fn validate_name(name: &str) -> Result<String, ApiTokenError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiTokenError::Invalid("The token name is required.".into()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(ApiTokenError::Invalid(format!(
            "The token name can have at most {MAX_NAME_LEN} characters."
        )));
    }
    if !crate::names::is_safe_name(name) {
        return Err(ApiTokenError::Invalid(
            "The token name can use letters, digits, spaces and - _ . ( ) : / only.".into(),
        ));
    }
    Ok(name.to_owned())
}

/// A fresh token. Its value is never stored.
fn generate() -> String {
    let mut secret = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret))
}

/// The stored form of `token`, or `None` when it cannot be an XGuard token.
#[must_use]
pub fn hash_token(token: &str) -> Option<String> {
    let secret = token.strip_prefix(TOKEN_PREFIX)?;
    if token.len() != TOKEN_LEN
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(crate::hex::to_lower_hex(&Sha256::digest(token.as_bytes())))
}

fn hint(token: &str) -> String {
    token[..TOKEN_PREFIX.len() + HINT_LEN].to_owned()
}

macro_rules! select_tokens {
    () => {
        "SELECT id, user_id, name, hint, created_at, expires_at, last_used_at, last_used_ip, \
         read_only FROM api_token "
    };
}

impl ApiToken {
    pub async fn find_by_user<'e, E: PgExecutor<'e>>(
        executor: E,
        user_id: Id,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(concat!(
            select_tokens!(),
            "WHERE user_id = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    pub async fn find_for_user<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
        user_id: Id,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(concat!(select_tokens!(), "WHERE id = $1 AND user_id = $2"))
            .bind(id)
            .bind(user_id)
            .fetch_optional(executor)
            .await
    }

    /// Creates a token for `user_id` and returns it with its secret value.
    ///
    /// Run it in a transaction: the per-user limit is checked under a lock on the user's row,
    /// so concurrent requests cannot exceed it.
    pub async fn create(
        conn: &mut sqlx::PgConnection,
        user_id: Id,
        input: &NewApiToken,
    ) -> Result<(Self, String), ApiTokenError> {
        let name = validate_name(&input.name)?;
        let expires_at = match input.expires_in_days {
            None => None,
            Some(days @ 1..=MAX_LIFETIME_DAYS) => {
                Some(Utc::now().naive_utc() + TimeDelta::days(i64::from(days)))
            }
            Some(_) => {
                return Err(ApiTokenError::Invalid(format!(
                    "A token can last from 1 to {MAX_LIFETIME_DAYS} days."
                )));
            }
        };

        sqlx::query(r#"SELECT 1 FROM "user" WHERE id = $1 FOR UPDATE"#)
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM api_token WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
        if count >= MAX_TOKENS_PER_USER {
            return Err(ApiTokenError::TooMany);
        }

        let token = generate();
        let hash = hash_token(&token).expect("generated tokens are well formed");
        let created: Self = sqlx::query_as(
            "INSERT INTO api_token (user_id, created_at, name, token_hash, hint, expires_at, \
             read_only) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, user_id, name, hint, created_at, expires_at, last_used_at, \
             last_used_ip, read_only",
        )
        .bind(user_id)
        .bind(Utc::now().naive_utc())
        .bind(name)
        .bind(hash)
        .bind(hint(&token))
        .bind(expires_at)
        .bind(input.read_only)
        .fetch_one(&mut *conn)
        .await?;
        Ok((created, token))
    }

    pub async fn rename<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
        user_id: Id,
        name: &str,
    ) -> Result<Self, ApiTokenError> {
        let name = validate_name(name)?;
        let row: Option<Self> = sqlx::query_as(
            "UPDATE api_token SET name = $3 WHERE id = $1 AND user_id = $2 \
             RETURNING id, user_id, name, hint, created_at, expires_at, last_used_at, \
             last_used_ip, read_only",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .fetch_optional(executor)
        .await?;
        row.ok_or(ApiTokenError::NotFound)
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
        user_id: Id,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            "DELETE FROM api_token WHERE id = $1 AND user_id = $2 \
             RETURNING id, user_id, name, hint, created_at, expires_at, last_used_at, \
             last_used_ip, read_only",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Revokes every token of `user_id`, returning how many there were.
    pub async fn delete_all_for_user<'e, E: PgExecutor<'e>>(
        executor: E,
        user_id: Id,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM api_token WHERE user_id = $1")
            .bind(user_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// Looks up the token presented in a request. Malformed values never reach the database.
    pub async fn authenticate<'e, E: PgExecutor<'e>>(
        executor: E,
        token: &str,
    ) -> Result<Option<TokenAuth>, sqlx::Error> {
        let Some(hash) = hash_token(token) else {
            return Ok(None);
        };
        sqlx::query_as(
            "SELECT id, user_id, read_only, expires_at, last_used_at FROM api_token \
             WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(executor)
        .await
    }

    /// Records a use of the token, unless one was recorded within the last minute.
    pub async fn record_use<'e, E: PgExecutor<'e>>(
        executor: E,
        auth: &TokenAuth,
        ip: IpAddr,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now().naive_utc();
        if !auth.last_use_is_stale(now) {
            return Ok(());
        }
        sqlx::query("UPDATE api_token SET last_used_at = $2, last_used_ip = $3 WHERE id = $1")
            .bind(auth.id)
            .bind(now)
            .bind(IpNetwork::from(ip))
            .execute(executor)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
