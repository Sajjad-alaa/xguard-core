//! RADIUS MFA settings and server-side Access-Challenge state.
//!
//! Uses runtime `sqlx::query` calls on dedicated tables (`radius_settings`,
//! `web_radius_challenge`, `vpn_mfa_radius_challenge`) so offline SQLx checks
//! on existing tables remain unaffected.

use std::net::IpAddr;

use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgExecutor, Row};

use crate::{db::Id, global_value, secret::SecretStringWrapper};

global_value!(
    RADIUS_SETTINGS,
    Option<RadiusSettings>,
    None,
    set_radius_settings,
    get_radius_settings
);

/// Loads the RADIUS settings into the in-memory cache at program start.
pub async fn initialize_radius_settings<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<()> {
    set_radius_settings(Some(RadiusSettings::load(executor).await?));
    Ok(())
}

/// How the XGuard user identifier is formatted into the RADIUS `User-Name` attribute.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RadiusUsernameFormat {
    #[default]
    Username,
    Email,
}

impl RadiusUsernameFormat {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
        }
    }

    #[must_use]
    pub fn from_db(raw: &str) -> Self {
        match raw {
            "email" => Self::Email,
            _ => Self::Username,
        }
    }

    #[must_use]
    pub fn resolve<'a>(self, username: &'a str, email: &'a str) -> &'a str {
        match self {
            Self::Username => username,
            Self::Email => {
                if email.is_empty() {
                    username
                } else {
                    email
                }
            }
        }
    }
}

/// Full stored RADIUS configuration (includes secrets — never serialize directly to API responses).
#[derive(Clone, Debug)]
pub struct RadiusSettings {
    pub enabled: bool,
    pub web_login_enabled: bool,
    pub vpn_mfa_enabled: bool,
    pub primary_host: String,
    pub primary_port: u16,
    pub primary_secret: SecretStringWrapper,
    pub secondary_host: Option<String>,
    pub secondary_port: u16,
    pub secondary_secret: Option<SecretStringWrapper>,
    pub timeout_secs: u64,
    pub retries: u8,
    pub nas_identifier: String,
    pub nas_ip_address: Option<IpAddr>,
    pub username_format: RadiusUsernameFormat,
    pub push_enabled: bool,
    pub push_poll_interval_secs: u32,
}

impl Default for RadiusSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            web_login_enabled: false,
            vpn_mfa_enabled: false,
            primary_host: String::new(),
            primary_port: 1812,
            primary_secret: SecretStringWrapper::from(""),
            secondary_host: None,
            secondary_port: 1812,
            secondary_secret: None,
            timeout_secs: 3,
            retries: 3,
            nas_identifier: "xguard".to_owned(),
            nas_ip_address: None,
            username_format: RadiusUsernameFormat::Username,
            push_enabled: false,
            push_poll_interval_secs: 2,
        }
    }
}

impl RadiusSettings {
    /// Whether primary host + secret are configured and the integration is enabled.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.enabled
            && !self.primary_host.trim().is_empty()
            && !self.primary_secret.expose_secret().is_empty()
    }

    #[must_use]
    pub fn is_web_login_ready(&self) -> bool {
        self.is_ready() && self.web_login_enabled
    }

    #[must_use]
    pub fn is_vpn_mfa_ready(&self) -> bool {
        self.is_ready() && self.vpn_mfa_enabled
    }

    /// Safe view for admin API responses: never includes shared secrets.
    #[must_use]
    pub fn to_view(&self) -> RadiusSettingsView {
        RadiusSettingsView {
            enabled: self.enabled,
            web_login_enabled: self.web_login_enabled,
            vpn_mfa_enabled: self.vpn_mfa_enabled,
            primary_host: self.primary_host.clone(),
            primary_port: self.primary_port,
            primary_secret_set: !self.primary_secret.expose_secret().is_empty(),
            secondary_host: self.secondary_host.clone(),
            secondary_port: self.secondary_port,
            secondary_secret_set: self
                .secondary_secret
                .as_ref()
                .is_some_and(|s| !s.expose_secret().is_empty()),
            timeout_secs: self.timeout_secs,
            retries: self.retries,
            nas_identifier: self.nas_identifier.clone(),
            nas_ip_address: self.nas_ip_address.map(|ip| ip.to_string()),
            username_format: self.username_format,
            push_enabled: self.push_enabled,
            push_poll_interval_secs: self.push_poll_interval_secs,
        }
    }

    /// Returns the cached RADIUS settings when initialized, or loads them directly from PostgreSQL.
    ///
    /// Before [`initialize_radius_settings`] has run (for instance in isolated `#[sqlx::test]`
    /// databases) this always reads from the database so separate test databases never share state.
    pub async fn get<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        if let Some(settings) = get_radius_settings().clone() {
            return Ok(settings);
        }
        Self::load(executor).await
    }

    /// Loads the singleton RADIUS settings row directly from PostgreSQL, returning defaults if not yet seeded.
    pub async fn load<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        let row = sqlx::query(
            r#"
            SELECT enabled, web_login_enabled, vpn_mfa_enabled,
                   primary_host, primary_port, primary_secret,
                   secondary_host, secondary_port, secondary_secret,
                   timeout_secs, retries, nas_identifier, nas_ip_address,
                   username_format, push_enabled, push_poll_interval_secs
            FROM radius_settings
            WHERE id = 1
            "#,
        )
        .fetch_optional(executor)
        .await?;

        let Some(row) = row else {
            return Ok(Self::default());
        };

        let nas_ip_raw: Option<String> = row.try_get("nas_ip_address")?;
        let nas_ip_address = nas_ip_raw
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<IpAddr>().ok());

        let primary_port = u16::try_from(row.try_get::<i32, _>("primary_port")?).unwrap_or(1812);
        let secondary_port =
            u16::try_from(row.try_get::<i32, _>("secondary_port")?).unwrap_or(1812);
        let timeout_secs = u64::try_from(row.try_get::<i32, _>("timeout_secs")?).unwrap_or(3);
        let retries = u8::try_from(row.try_get::<i16, _>("retries")?).unwrap_or(3);
        let push_poll_interval_secs =
            u32::try_from(row.try_get::<i32, _>("push_poll_interval_secs")?).unwrap_or(2);
        let secondary_secret: Option<String> = row.try_get("secondary_secret")?;

        Ok(Self {
            enabled: row.try_get("enabled")?,
            web_login_enabled: row.try_get("web_login_enabled")?,
            vpn_mfa_enabled: row.try_get("vpn_mfa_enabled")?,
            primary_host: row.try_get("primary_host")?,
            primary_port,
            primary_secret: SecretStringWrapper::from(row.try_get::<String, _>("primary_secret")?),
            secondary_host: row.try_get("secondary_host")?,
            secondary_port,
            secondary_secret: secondary_secret
                .filter(|s| !s.is_empty())
                .map(SecretStringWrapper::from),
            timeout_secs,
            retries,
            nas_identifier: row.try_get("nas_identifier")?,
            nas_ip_address,
            username_format: RadiusUsernameFormat::from_db(
                &row.try_get::<String, _>("username_format")?,
            ),
            push_enabled: row.try_get("push_enabled")?,
            push_poll_interval_secs,
        })
    }

    /// Saves the singleton RADIUS settings row.
    pub async fn save<'e, E: PgExecutor<'e>>(&self, executor: E) -> sqlx::Result<()> {
        let secondary_host = self
            .secondary_host
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let secondary_secret = self
            .secondary_secret
            .as_ref()
            .map(|s| s.expose_secret())
            .filter(|s| !s.is_empty());
        let nas_ip = self.nas_ip_address.map(|ip| ip.to_string());

        sqlx::query(
            r#"
            INSERT INTO radius_settings (
                id, enabled, web_login_enabled, vpn_mfa_enabled,
                primary_host, primary_port, primary_secret,
                secondary_host, secondary_port, secondary_secret,
                timeout_secs, retries, nas_identifier, nas_ip_address,
                username_format, push_enabled, push_poll_interval_secs, updated_at
            )
            VALUES (
                1, $1, $2, $3,
                $4, $5, $6,
                $7, $8, $9,
                $10, $11, $12, $13,
                $14, $15, $16, CURRENT_TIMESTAMP
            )
            ON CONFLICT (id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                web_login_enabled = EXCLUDED.web_login_enabled,
                vpn_mfa_enabled = EXCLUDED.vpn_mfa_enabled,
                primary_host = EXCLUDED.primary_host,
                primary_port = EXCLUDED.primary_port,
                primary_secret = EXCLUDED.primary_secret,
                secondary_host = EXCLUDED.secondary_host,
                secondary_port = EXCLUDED.secondary_port,
                secondary_secret = EXCLUDED.secondary_secret,
                timeout_secs = EXCLUDED.timeout_secs,
                retries = EXCLUDED.retries,
                nas_identifier = EXCLUDED.nas_identifier,
                nas_ip_address = EXCLUDED.nas_ip_address,
                username_format = EXCLUDED.username_format,
                push_enabled = EXCLUDED.push_enabled,
                push_poll_interval_secs = EXCLUDED.push_poll_interval_secs,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(self.enabled)
        .bind(self.web_login_enabled)
        .bind(self.vpn_mfa_enabled)
        .bind(self.primary_host.trim())
        .bind(i32::from(self.primary_port))
        .bind(self.primary_secret.expose_secret())
        .bind(secondary_host)
        .bind(i32::from(self.secondary_port))
        .bind(secondary_secret)
        .bind(i32::try_from(self.timeout_secs).unwrap_or(3))
        .bind(i16::from(self.retries))
        .bind(self.nas_identifier.trim())
        .bind(nas_ip)
        .bind(self.username_format.as_str())
        .bind(self.push_enabled)
        .bind(i32::try_from(self.push_poll_interval_secs).unwrap_or(2))
        .execute(executor)
        .await?;

        self.clone().set_cached();
        Ok(())
    }

    /// Updates the in-memory RADIUS settings cache if it has been initialized.
    pub fn set_cached(self) {
        let mut cache = RADIUS_SETTINGS
            .write()
            .expect("Failed to acquire RADIUS_SETTINGS RwLock for write");
        if cache.is_some() {
            *cache = Some(self);
        }
    }
}

/// Safe API representation of RADIUS settings (never leaks shared secrets).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RadiusSettingsView {
    pub enabled: bool,
    pub web_login_enabled: bool,
    pub vpn_mfa_enabled: bool,
    pub primary_host: String,
    pub primary_port: u16,
    pub primary_secret_set: bool,
    pub secondary_host: Option<String>,
    pub secondary_port: u16,
    pub secondary_secret_set: bool,
    pub timeout_secs: u64,
    pub retries: u8,
    pub nas_identifier: String,
    pub nas_ip_address: Option<String>,
    pub username_format: RadiusUsernameFormat,
    pub push_enabled: bool,
    pub push_poll_interval_secs: u32,
}

/// Server-side RADIUS Access-Challenge `State` bound to a web login session.
#[derive(Clone, Debug)]
pub struct WebRadiusChallenge {
    pub session_id: String,
    pub state: Vec<u8>,
    pub reply_message: Option<String>,
    pub expires_at: NaiveDateTime,
}

impl WebRadiusChallenge {
    pub async fn find_active<'e, E: PgExecutor<'e>>(
        executor: E,
        session_id: &str,
    ) -> sqlx::Result<Option<Self>> {
        let now = Utc::now().naive_utc();
        let row = sqlx::query(
            r#"
            SELECT session_id, state, reply_message, expires_at
            FROM web_radius_challenge
            WHERE session_id = $1 AND expires_at > $2
            "#,
        )
        .bind(session_id)
        .bind(now)
        .fetch_optional(executor)
        .await?;

        Ok(match row {
            Some(row) => Some(Self {
                session_id: row.try_get("session_id")?,
                state: row.try_get("state")?,
                reply_message: row.try_get("reply_message")?,
                expires_at: row.try_get("expires_at")?,
            }),
            None => None,
        })
    }

    pub async fn upsert<'e, E: PgExecutor<'e>>(
        executor: E,
        session_id: &str,
        state: &[u8],
        reply_message: Option<&str>,
        ttl: Duration,
    ) -> sqlx::Result<()> {
        let expires_at = Utc::now().naive_utc() + ttl;
        sqlx::query(
            r#"
            INSERT INTO web_radius_challenge (session_id, state, reply_message, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (session_id) DO UPDATE SET
                state = EXCLUDED.state,
                reply_message = EXCLUDED.reply_message,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(session_id)
        .bind(state)
        .bind(reply_message)
        .bind(expires_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(executor: E, session_id: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM web_radius_challenge WHERE session_id = $1")
            .bind(session_id)
            .execute(executor)
            .await?;
        Ok(())
    }
}

/// Server-side RADIUS Access-Challenge `State` bound to a VPN client MFA session attempt.
#[derive(Clone, Debug)]
pub struct VpnMfaRadiusChallenge {
    pub session_id: Id,
    pub step_attempt_id: String,
    pub state: Vec<u8>,
    pub reply_message: Option<String>,
}

impl VpnMfaRadiusChallenge {
    pub async fn find_for_attempt<'e, E: PgExecutor<'e>>(
        executor: E,
        session_id: Id,
        step_attempt_id: &str,
    ) -> sqlx::Result<Option<Self>> {
        let row = sqlx::query(
            r#"
            SELECT session_id, step_attempt_id, state, reply_message
            FROM vpn_mfa_radius_challenge
            WHERE session_id = $1 AND step_attempt_id = $2
            "#,
        )
        .bind(session_id)
        .bind(step_attempt_id)
        .fetch_optional(executor)
        .await?;

        Ok(match row {
            Some(row) => Some(Self {
                session_id: row.try_get("session_id")?,
                step_attempt_id: row.try_get("step_attempt_id")?,
                state: row.try_get("state")?,
                reply_message: row.try_get("reply_message")?,
            }),
            None => None,
        })
    }

    pub async fn upsert<'e, E: PgExecutor<'e>>(
        executor: E,
        session_id: Id,
        step_attempt_id: &str,
        state: &[u8],
        reply_message: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO vpn_mfa_radius_challenge (session_id, step_attempt_id, state, reply_message, updated_at)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
            ON CONFLICT (session_id) DO UPDATE SET
                step_attempt_id = EXCLUDED.step_attempt_id,
                state = EXCLUDED.state,
                reply_message = EXCLUDED.reply_message,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(session_id)
        .bind(step_attempt_id)
        .bind(state)
        .bind(reply_message)
        .execute(executor)
        .await?;
        Ok(())
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(executor: E, session_id: Id) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM vpn_mfa_radius_challenge WHERE session_id = $1")
            .bind(session_id)
            .execute(executor)
            .await?;
        Ok(())
    }
}
