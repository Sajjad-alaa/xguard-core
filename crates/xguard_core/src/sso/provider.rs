//! The external OpenID Connect provider users can sign in with (one at a time).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, Type};
use url::Url;
use xguard_common::db::Id;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "openid_provider_kind")]
pub enum ProviderKind {
    Custom,
    Google,
    Microsoft,
    Okta,
    JumpCloud,
    Zitadel,
}

/// The provider as the API shows it: the client secret is never returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OpenIdProvider {
    pub id: Id,
    pub kind: ProviderKind,
    /// The issuer URL; its `/.well-known/openid-configuration` describes the provider.
    pub issuer: String,
    pub client_id: String,
    pub enabled: bool,
    /// Shown on the sign-in button ("Sign in with …").
    pub display_name: Option<String>,
    /// Users who sign in through the provider and have no XGuard password cannot set one.
    pub disable_password_management: bool,
    pub client_secret_set: bool,
}

/// The provider with its secret, for the sign-in flow.
#[derive(Clone)]
pub struct ProviderConfig {
    pub provider: OpenIdProvider,
    pub client_secret: String,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderInput {
    pub kind: ProviderKind,
    pub issuer: String,
    pub client_id: String,
    /// Leave it out to keep the stored secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub disable_password_management: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("{0}")]
    Invalid(String),
    #[error("No OpenID provider is configured")]
    NotFound,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::Invalid(message.into())
}

/// HTTPS, or HTTP to this machine (for development and tests).
pub(crate) fn is_trusted_url(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        })
}

impl ProviderInput {
    /// Checks the input; `stored_secret` is kept when no new secret is given.
    pub fn validate(
        self,
        stored_secret: Option<String>,
    ) -> Result<(ProviderInput, String), ProviderError> {
        let issuer =
            Url::parse(self.issuer.trim()).map_err(|_| invalid("The issuer URL is not valid."))?;
        if !is_trusted_url(&issuer) {
            return Err(invalid("The issuer must be an https:// URL."));
        }
        if issuer.query().is_some() || issuer.fragment().is_some() {
            return Err(invalid("The issuer URL cannot have a query or fragment."));
        }
        let client_id = self.client_id.trim().to_owned();
        if client_id.is_empty() || client_id.len() > 512 {
            return Err(invalid("The client ID is required."));
        }
        let secret = match self.client_secret.map(|s| s.trim().to_owned()) {
            Some(secret) if !secret.is_empty() => secret,
            _ => stored_secret.ok_or_else(|| invalid("The client secret is required."))?,
        };
        let display_name = self
            .display_name
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty());
        if let Some(name) = &display_name
            && (name.chars().count() > 64 || !xguard_common::names::is_safe_name(name))
        {
            return Err(invalid(
                "Use a display name of up to 64 letters, digits, spaces and - _ . ( ) : /.",
            ));
        }
        // Store the issuer exactly as given (minus surrounding spaces): ID tokens must match it.
        let issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        Ok((
            ProviderInput {
                kind: self.kind,
                issuer,
                client_id,
                client_secret: None,
                enabled: self.enabled,
                display_name,
                disable_password_management: self.disable_password_management,
            },
            secret,
        ))
    }
}

#[derive(FromRow)]
struct Row {
    id: Id,
    kind: ProviderKind,
    base_url: String,
    client_id: String,
    client_secret: String,
    enabled: bool,
    display_name: Option<String>,
    disable_password_management: bool,
}

impl Row {
    fn into_config(self) -> ProviderConfig {
        ProviderConfig {
            provider: OpenIdProvider {
                id: self.id,
                kind: self.kind,
                issuer: self.base_url,
                client_id: self.client_id,
                enabled: self.enabled,
                display_name: self.display_name,
                disable_password_management: self.disable_password_management,
                client_secret_set: !self.client_secret.is_empty(),
            },
            client_secret: self.client_secret,
        }
    }
}

impl ProviderConfig {
    /// The configured provider, if any.
    pub async fn current<'e, E: PgExecutor<'e>>(executor: E) -> Result<Option<Self>, sqlx::Error> {
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, kind, base_url, client_id, client_secret, enabled, display_name, \
             disable_password_management FROM openidprovider ORDER BY id LIMIT 1",
        )
        .fetch_optional(executor)
        .await?;
        Ok(row.map(Row::into_config))
    }

    /// The provider users can sign in with now.
    pub async fn enabled<'e, E: PgExecutor<'e>>(executor: E) -> Result<Option<Self>, sqlx::Error> {
        Ok(Self::current(executor)
            .await?
            .filter(|config| config.provider.enabled))
    }

    /// Creates or replaces the provider. There is only ever one.
    pub async fn save(
        conn: &mut sqlx::PgConnection,
        input: ProviderInput,
    ) -> Result<OpenIdProvider, ProviderError> {
        let current = Self::current(&mut *conn).await?;
        let (input, secret) = input.validate(current.as_ref().map(|c| c.client_secret.clone()))?;
        let name = input
            .display_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", input.kind));
        // Remove the old provider first: there is only ever one, and the table has unique
        // constraints on its fields.
        if let Some(current) = &current {
            sqlx::query("DELETE FROM openidprovider")
                .execute(&mut *conn)
                .await?;
            // A subject identifier is only unique within its issuer. With a new issuer, old links
            // could match the wrong person, so users link again through their verified email.
            if !current.provider.issuer.eq_ignore_ascii_case(&input.issuer) {
                let unlinked = sqlx::query(
                    r#"UPDATE "user" SET openid_sub = NULL WHERE openid_sub IS NOT NULL"#,
                )
                .execute(&mut *conn)
                .await?;
                info!(
                    "The OpenID issuer changed; unlinked {} users",
                    unlinked.rows_affected()
                );
            }
        }
        let row: Row = sqlx::query_as(
            "INSERT INTO openidprovider (name, kind, base_url, client_id, client_secret, enabled, \
             display_name, disable_password_management) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id, kind, base_url, client_id, client_secret, enabled, display_name, \
             disable_password_management",
        )
        .bind(name)
        .bind(input.kind)
        .bind(&input.issuer)
        .bind(&input.client_id)
        .bind(secret)
        .bind(input.enabled)
        .bind(&input.display_name)
        .bind(input.disable_password_management)
        .fetch_one(&mut *conn)
        .await?;
        Ok(row.into_config().provider)
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(
        executor: E,
    ) -> Result<OpenIdProvider, ProviderError> {
        let row: Option<Row> = sqlx::query_as(
            "DELETE FROM openidprovider RETURNING id, kind, base_url, client_id, client_secret, \
             enabled, display_name, disable_password_management",
        )
        .fetch_optional(executor)
        .await?;
        row.map(|row| row.into_config().provider)
            .ok_or(ProviderError::NotFound)
    }
}

/// Whether users of the provider without a local password are barred from setting one.
pub async fn disables_password_management<'e, E: PgExecutor<'e>>(
    executor: E,
) -> Result<bool, sqlx::Error> {
    Ok(ProviderConfig::enabled(executor)
        .await?
        .is_some_and(|config| config.provider.disable_password_management))
}
