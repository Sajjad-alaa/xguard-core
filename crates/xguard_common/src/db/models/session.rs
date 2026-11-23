use chrono::{NaiveDateTime, TimeDelta, Utc};
use sqlx::{PgExecutor, PgPool, Type, query, query_as};
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::{
    db::{Id, models::Settings},
    random::gen_alphanumeric,
};

#[derive(Clone, PartialEq, Type)]
#[repr(i16)]
pub enum SessionState {
    // Discriminants are pinned because they are stored in the `session.state` column.
    PasswordVerified = 1,
    MultiFactorVerified = 2,
    ApiTokenVerified = 3,
}

/// Representation of a XGuard server user session derived from session cookies.
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user_id: Id,
    pub state: SessionState,
    pub created: NaiveDateTime,
    pub expires: NaiveDateTime,
    pub webauthn_challenge: Option<Vec<u8>>,
    pub ip_address: String,
    pub device_info: Option<String>,
}

impl Session {
    #[must_use]
    pub fn new(
        user_id: Id,
        state: SessionState,
        ip_address: String,
        device_info: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let settings = Settings::get_current_settings();
        let timeout = settings.authentication_timeout();
        Self {
            id: gen_alphanumeric(24),
            user_id,
            state,
            created: now.naive_utc(),
            expires: (now + TimeDelta::seconds(timeout.as_secs() as i64)).naive_utc(),
            webauthn_challenge: None,
            ip_address,
            device_info,
        }
    }

    #[must_use]
    pub fn expired(&self) -> bool {
        self.expires < Utc::now().naive_utc()
    }

    pub async fn find_by_id(pool: &PgPool, id: &str) -> sqlx::Result<Option<Self>> {
        query_as!(
            Self,
            "SELECT id, user_id, state \"state: SessionState\", created, expires, \
            webauthn_challenge, \
            ip_address, device_info FROM session WHERE id = $1",
            id
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn save(&self, pool: &PgPool) -> sqlx::Result<()> {
        query!(
            "INSERT INTO session (id, user_id, state, created, expires, webauthn_challenge, \
            ip_address, device_info) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            self.id,
            self.user_id,
            self.state.clone() as i16,
            self.created,
            self.expires,
            self.webauthn_challenge,
            self.ip_address,
            self.device_info,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn set_state(&mut self, pool: &PgPool, state: SessionState) -> sqlx::Result<()> {
        query!(
            "UPDATE session SET state = $1 WHERE id = $2",
            state.clone() as i16,
            self.id
        )
        .execute(pool)
        .await?;
        self.state = state;

        Ok(())
    }

    #[must_use]
    pub fn get_passkey_registration(&self) -> Option<PasskeyRegistration> {
        self.webauthn_challenge
            .as_ref()
            .and_then(|challenge| serde_cbor::from_slice(challenge).ok())
    }

    #[must_use]
    pub fn get_passkey_authentication(&self) -> Option<PasskeyAuthentication> {
        self.webauthn_challenge
            .as_ref()
            .and_then(|challenge| serde_cbor::from_slice(challenge).ok())
    }

    pub async fn set_passkey_authentication<'e, E>(
        &mut self,
        executor: E,
        passkey_auth: &PasskeyAuthentication,
    ) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        if let Ok(webauthn_challenge) = serde_cbor::to_vec(passkey_auth) {
            query!(
                "UPDATE session SET webauthn_challenge = $1 WHERE id = $2",
                webauthn_challenge,
                self.id
            )
            .execute(executor)
            .await?;
            self.webauthn_challenge = Some(webauthn_challenge);
        }

        Ok(())
    }

    pub async fn set_passkey_registration<'e, E>(
        &mut self,
        executor: E,
        passkey_reg: &PasskeyRegistration,
    ) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        if let Ok(webauthn_challenge) = serde_cbor::to_vec(passkey_reg) {
            query!(
                "UPDATE session SET webauthn_challenge = $1 WHERE id = $2",
                webauthn_challenge,
                self.id
            )
            .execute(executor)
            .await?;
            self.webauthn_challenge = Some(webauthn_challenge);
        }

        Ok(())
    }

    pub async fn delete<'e, E>(self, executor: E) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        query!("DELETE FROM session WHERE id = $1", self.id)
            .execute(executor)
            .await?;

        Ok(())
    }

    /// Atomically removes and returns `webauthn_challenge` so any WebAuthn ceremony challenge
    /// can be consumed at most once.
    pub async fn take_webauthn_challenge(
        &mut self,
        pool: &PgPool,
    ) -> sqlx::Result<Option<Vec<u8>>> {
        let mut transaction = pool.begin().await?;
        let challenge: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT webauthn_challenge FROM session WHERE id = $1 FOR UPDATE")
                .bind(&self.id)
                .fetch_optional(&mut *transaction)
                .await?;
        let Some(Some(challenge)) = challenge else {
            return Ok(None);
        };
        sqlx::query("UPDATE session SET webauthn_challenge = NULL WHERE id = $1")
            .bind(&self.id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        self.webauthn_challenge = None;
        Ok(Some(challenge))
    }

    pub async fn take_passkey_registration(
        &mut self,
        pool: &PgPool,
    ) -> sqlx::Result<Option<PasskeyRegistration>> {
        Ok(self
            .take_webauthn_challenge(pool)
            .await?
            .and_then(|bytes| serde_cbor::from_slice(&bytes).ok()))
    }

    pub async fn take_passkey_authentication(
        &mut self,
        pool: &PgPool,
    ) -> sqlx::Result<Option<PasskeyAuthentication>> {
        Ok(self
            .take_webauthn_challenge(pool)
            .await?
            .and_then(|bytes| serde_cbor::from_slice(&bytes).ok()))
    }

    pub async fn delete_expired<'e, E>(executor: E) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        query!("DELETE FROM session WHERE expires < now()",)
            .execute(executor)
            .await?;

        Ok(())
    }

    pub async fn delete_all_for_user<'e, E>(executor: E, user_id: Id) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        query!("DELETE FROM session WHERE user_id = $1", user_id)
            .execute(executor)
            .await?;

        Ok(())
    }

    pub async fn delete_all_for_user_except<'e, E>(
        executor: E,
        user_id: Id,
        session_id: &str,
    ) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        query!(
            "DELETE FROM session WHERE user_id = $1 AND id != $2",
            user_id,
            session_id
        )
        .execute(executor)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;
    use crate::db::{
        models::{User, settings::initialize_current_settings},
        setup_pool,
    };

    #[sqlx::test]
    async fn test_take_webauthn_challenge_is_single_use(
        _: PgPoolOptions,
        options: PgConnectOptions,
    ) {
        let pool = setup_pool(options).await;
        initialize_current_settings(&pool).await.unwrap();
        let user = User::new(
            "challenge_user",
            Some("pass123"),
            "Tester",
            "Challenge",
            "challenge@example.com",
            None,
        )
        .save(&pool)
        .await
        .unwrap();

        let mut session = Session::new(
            user.id,
            SessionState::PasswordVerified,
            "127.0.0.1".into(),
            None,
        );
        session.save(&pool).await.unwrap();

        let raw = vec![1u8, 2, 3, 4];
        sqlx::query("UPDATE session SET webauthn_challenge = $1 WHERE id = $2")
            .bind(&raw)
            .bind(&session.id)
            .execute(&pool)
            .await
            .unwrap();

        let first = session.take_webauthn_challenge(&pool).await.unwrap();
        assert_eq!(first, Some(raw));
        let second = session.take_webauthn_challenge(&pool).await.unwrap();
        assert!(second.is_none());
    }
}
