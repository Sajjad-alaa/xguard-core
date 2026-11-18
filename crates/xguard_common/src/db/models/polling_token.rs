use chrono::{NaiveDateTime, Utc};
use model_derive::Model;
use sha2::{Digest, Sha256};
use sqlx::{PgExecutor, query_as};

use crate::{
    db::{Id, NoId},
    random::gen_alphanumeric,
};

/// Length of the secret handed to the client.
const TOKEN_LENGTH: usize = 32;
/// Upper bound on a presented token, so a huge input is refused before it is hashed.
pub const MAX_PRESENTED_TOKEN_LENGTH: usize = 256;

/// Token a desktop client uses for configuration polling and other device-authenticated requests.
///
/// Only a SHA-256 digest of the secret is stored (hex, in `token`): a leaked database does not
/// reveal usable tokens, and lookups go by the digest of the presented value, which an attacker
/// cannot steer, so the lookup leaks nothing useful through timing.
#[derive(Clone, Debug, Model)]
pub struct PollingToken<I = NoId> {
    pub id: I,
    /// Hex SHA-256 digest of the secret.
    pub token: String,
    pub device_id: Id,
    pub created_at: NaiveDateTime,
}

/// Hex SHA-256 digest of a polling token, as stored in the database.
#[must_use]
pub fn polling_token_digest(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

impl PollingToken {
    /// A new token for `device_id`. Returns the model to save (holding only the digest) and the
    /// secret to hand to the client, which is not kept anywhere else.
    #[must_use]
    pub fn new(device_id: Id) -> (Self, String) {
        let secret = gen_alphanumeric(TOKEN_LENGTH);
        (
            Self {
                id: NoId,
                device_id,
                token: polling_token_digest(&secret),
                created_at: Utc::now().naive_utc(),
            },
            secret,
        )
    }
}

impl PollingToken<Id> {
    /// Finds the token matching the presented secret.
    pub async fn find<'e, E>(executor: E, token: &str) -> sqlx::Result<Option<Self>>
    where
        E: PgExecutor<'e>,
    {
        if token.is_empty() || token.len() > MAX_PRESENTED_TOKEN_LENGTH {
            return Ok(None);
        }
        let digest = polling_token_digest(token);
        let found = query_as!(
            Self,
            "SELECT id, token, device_id, created_at \
            FROM pollingtoken WHERE token = $1",
            digest
        )
        .fetch_optional(executor)
        .await?;
        // The index lookup already matched; compare again without early exit as defence in depth.
        Ok(found.filter(|found| constant_time_eq(found.token.as_bytes(), digest.as_bytes())))
    }

    /// Whether `token` is the secret behind this stored digest (constant time).
    #[must_use]
    pub fn matches(&self, token: &str) -> bool {
        token.len() <= MAX_PRESENTED_TOKEN_LENGTH
            && constant_time_eq(
                self.token.as_bytes(),
                polling_token_digest(token).as_bytes(),
            )
    }

    pub async fn delete_for_device_id<'e, E>(executor: E, device_id: Id) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query!("DELETE FROM pollingtoken WHERE device_id = $1", device_id)
            .execute(executor)
            .await?;
        Ok(())
    }
}

/// Compares two byte strings without an early exit.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_hex() {
        let digest = polling_token_digest("abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn new_token_stores_only_the_digest() {
        let (model, secret) = PollingToken::new(1);
        assert_eq!(secret.len(), TOKEN_LENGTH);
        assert_ne!(model.token, secret);
        assert_eq!(model.token, polling_token_digest(&secret));
    }

    #[test]
    fn matches_is_exact() {
        let (model, secret) = PollingToken::new(7);
        let model = PollingToken::<Id> {
            id: 1,
            token: model.token,
            device_id: 7,
            created_at: model.created_at,
        };
        assert!(model.matches(&secret));
        assert!(!model.matches(&secret[1..]));
        assert!(!model.matches(""));
        assert!(!model.matches(&"a".repeat(MAX_PRESENTED_TOKEN_LENGTH + 1)));
        assert!(constant_time_eq(b"x", b"x"));
        assert!(!constant_time_eq(b"x", b"xy"));
    }
}
