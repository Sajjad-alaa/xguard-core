//! The external OpenID Connect provider users can sign in with (one at a time).

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgExecutor, Type};
use tracing::info;
use url::Url;
use xguard_common::db::Id;

use crate::dirsync::settings::{
    DirectorySyncInput, DirectorySyncSecrets, DirectorySyncSettings, MissingUserAction, SyncTarget,
};

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

impl From<ProviderKind> for xguard_proto::client_types::OpenIdProviderKind {
    fn from(kind: ProviderKind) -> Self {
        match kind {
            ProviderKind::Custom => Self::Custom,
            ProviderKind::Google => Self::Google,
            ProviderKind::Microsoft => Self::Microsoft,
            ProviderKind::Okta => Self::Okta,
            ProviderKind::JumpCloud => Self::Jumpcloud,
            ProviderKind::Zitadel => Self::Zitadel,
        }
    }
}

/// The provider as the API shows it: the client secret and directory credentials are never
/// returned.
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
    #[serde(flatten)]
    pub directory_sync: DirectorySyncSettings,
}

impl OpenIdProvider {
    /// The name activity log entries use for this provider.
    #[must_use]
    pub fn label(&self) -> String {
        self.display_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", self.kind))
    }
}

/// The provider with its secrets, for the sign-in flow and the directory sync.
#[derive(Clone)]
pub struct ProviderConfig {
    pub provider: OpenIdProvider,
    pub client_secret: String,
    pub directory_secrets: DirectorySyncSecrets,
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
    #[serde(flatten)]
    pub directory_sync: DirectorySyncInput,
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

pub(crate) fn allow_insecure_loopback() -> bool {
    cfg!(any(test, debug_assertions))
        || std::env::var("XGUARD_ALLOW_INSECURE_LOOPBACK_OIDC")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

pub(crate) fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_link_local() || mapped.is_unspecified();
            }
            v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub(crate) fn is_blocked_resolved_ip(ip: IpAddr) -> bool {
    is_blocked_ip(ip) || (is_loopback_ip(ip) && !allow_insecure_loopback())
}

pub(crate) async fn resolve_and_validate_host(
    host: &str,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    let bare_host = host.trim_start_matches('[').trim_end_matches(']');
    let is_literal = bare_host.parse::<IpAddr>().is_ok();
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare_host, 0)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "host resolved to no addresses",
        ));
    }
    for addr in &addrs {
        let ip = addr.ip();
        if is_blocked_resolved_ip(ip)
            || (!is_literal && !bare_host.eq_ignore_ascii_case("localhost") && is_loopback_ip(ip))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "resolved to a blocked IP address",
            ));
        }
    }
    Ok(addrs)
}

/// HTTPS, or HTTP to this machine when explicitly permitted (for development and tests).
/// Link-local and unspecified addresses are rejected even over HTTPS.
pub(crate) fn is_trusted_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let bare_host = host.trim_start_matches('[').trim_end_matches(']');
    let parsed_ip = bare_host.parse::<IpAddr>().ok();
    if parsed_ip.is_some_and(is_blocked_ip) {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    url.scheme() == "http"
        && allow_insecure_loopback()
        && (bare_host.eq_ignore_ascii_case("localhost") || parsed_ip.is_some_and(is_loopback_ip))
}

pub(crate) fn same_origin(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (Url::parse(a), Url::parse(b)) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
        && a.port_or_known_default() == b.port_or_known_default()
}

impl ProviderInput {
    /// Checks the input and builds the provider it describes. Secrets that are not given are
    /// kept from `stored`; the id is the stored provider's (0 for a new one).
    pub fn into_config(
        self,
        stored: Option<&ProviderConfig>,
    ) -> Result<ProviderConfig, ProviderError> {
        let issuer =
            Url::parse(self.issuer.trim()).map_err(|_| invalid("The issuer URL is not valid."))?;
        if !is_trusted_url(&issuer) {
            return Err(invalid("The issuer must be an https:// URL."));
        }
        if issuer.query().is_some() || issuer.fragment().is_some() {
            return Err(invalid("The issuer URL cannot have a query or fragment."));
        }
        // Store the issuer verbatim (minus surrounding whitespace) so issuers with trailing
        // slashes (e.g. Auth0) keep matching ID tokens' `iss` claim.
        let issuer = self.issuer.trim().to_owned();
        let reusable_stored = stored.filter(|config| {
            config.provider.kind == self.kind && same_origin(&config.provider.issuer, &issuer)
        });
        let client_id = self.client_id.trim().to_owned();
        if client_id.is_empty() || client_id.len() > 512 {
            return Err(invalid("The client ID is required."));
        }
        let secret = match self.client_secret.map(|s| s.trim().to_owned()) {
            Some(secret) if !secret.is_empty() => secret,
            _ => reusable_stored
                .map(|config| config.client_secret.clone())
                .ok_or_else(|| invalid("The client secret is required."))?,
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
        let no_secrets = DirectorySyncSecrets::default();
        let (directory_sync, directory_secrets) = self.directory_sync.validate(
            self.kind,
            &issuer,
            reusable_stored.map_or(&no_secrets, |config| &config.directory_secrets),
        )?;
        Ok(ProviderConfig {
            provider: OpenIdProvider {
                id: stored.map_or(0, |config| config.provider.id),
                kind: self.kind,
                issuer,
                client_id,
                enabled: self.enabled,
                display_name,
                disable_password_management: self.disable_password_management,
                client_secret_set: true,
                directory_sync,
            },
            client_secret: secret,
            directory_secrets,
        })
    }
}

/// The columns [`Row`] reads, for every statement that returns the provider.
macro_rules! provider_columns {
    () => {
        "id, kind, base_url, client_id, client_secret, enabled, display_name, \
         disable_password_management, directory_sync_enabled, directory_sync_interval, \
         directory_sync_user_behavior, directory_sync_admin_behavior, directory_sync_target, \
         directory_sync_group_match, directory_sync_user_groups, prefetch_users, admin_email, \
         google_service_account_email, google_service_account_key, okta_dirsync_client_id, \
         okta_private_jwk, jumpcloud_api_key"
    };
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
    directory_sync_enabled: bool,
    directory_sync_interval: i32,
    directory_sync_user_behavior: MissingUserAction,
    directory_sync_admin_behavior: MissingUserAction,
    directory_sync_target: SyncTarget,
    directory_sync_group_match: Vec<String>,
    directory_sync_user_groups: Option<Vec<String>>,
    prefetch_users: bool,
    admin_email: Option<String>,
    google_service_account_email: Option<String>,
    google_service_account_key: Option<String>,
    okta_dirsync_client_id: Option<String>,
    okta_private_jwk: Option<String>,
    jumpcloud_api_key: Option<String>,
}

impl Row {
    fn into_config(self) -> ProviderConfig {
        let non_empty = |value: Option<String>| value.filter(|value| !value.is_empty());
        let directory_secrets = DirectorySyncSecrets {
            google_service_account_key: non_empty(self.google_service_account_key),
            okta_private_jwk: non_empty(self.okta_private_jwk),
            jumpcloud_api_key: non_empty(self.jumpcloud_api_key),
        };
        let mut directory_sync = DirectorySyncSettings {
            directory_sync_enabled: self.directory_sync_enabled,
            directory_sync_interval: self.directory_sync_interval,
            directory_sync_user_behavior: self.directory_sync_user_behavior,
            directory_sync_admin_behavior: self.directory_sync_admin_behavior,
            directory_sync_target: self.directory_sync_target,
            directory_sync_group_match: self.directory_sync_group_match,
            directory_sync_user_groups: self.directory_sync_user_groups.unwrap_or_default(),
            prefetch_users: self.prefetch_users,
            admin_email: self.admin_email,
            google_service_account_email: self.google_service_account_email,
            okta_dirsync_client_id: self.okta_dirsync_client_id,
            ..DirectorySyncSettings::default()
        };
        directory_secrets.mark_set(&mut directory_sync);
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
                directory_sync,
            },
            client_secret: self.client_secret,
            directory_secrets,
        }
    }
}

impl ProviderConfig {
    /// The configured provider, if any.
    pub async fn current<'e, E: PgExecutor<'e>>(executor: E) -> Result<Option<Self>, sqlx::Error> {
        let row: Option<Row> = sqlx::query_as(concat!(
            "SELECT ",
            provider_columns!(),
            " FROM openidprovider ORDER BY id LIMIT 1"
        ))
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

    /// Creates or updates the provider. There is only ever one, and it keeps its id, so the
    /// directory identities that refer to it stay valid.
    pub async fn save(
        conn: &mut sqlx::PgConnection,
        input: ProviderInput,
    ) -> Result<OpenIdProvider, ProviderError> {
        let current = Self::current(&mut *conn).await?;
        let config = input.into_config(current.as_ref())?;
        let provider = &config.provider;
        let sync = &provider.directory_sync;
        let secrets = &config.directory_secrets;
        let name = provider.label();
        let statement = if current.is_some() {
            concat!(
                "UPDATE openidprovider SET name = $1, kind = $2, base_url = $3, client_id = $4, \
                 client_secret = $5, enabled = $6, display_name = $7, \
                 disable_password_management = $8, directory_sync_enabled = $9, \
                 directory_sync_interval = $10, directory_sync_user_behavior = $11, \
                 directory_sync_admin_behavior = $12, directory_sync_target = $13, \
                 directory_sync_group_match = $14, directory_sync_user_groups = $15, \
                 prefetch_users = $16, admin_email = $17, google_service_account_email = $18, \
                 google_service_account_key = $19, okta_dirsync_client_id = $20, \
                 okta_private_jwk = $21, jumpcloud_api_key = $22 WHERE id = $23 RETURNING ",
                provider_columns!()
            )
        } else {
            concat!(
                "INSERT INTO openidprovider (name, kind, base_url, client_id, client_secret, \
                 enabled, display_name, disable_password_management, directory_sync_enabled, \
                 directory_sync_interval, directory_sync_user_behavior, \
                 directory_sync_admin_behavior, directory_sync_target, \
                 directory_sync_group_match, directory_sync_user_groups, prefetch_users, \
                 admin_email, google_service_account_email, google_service_account_key, \
                 okta_dirsync_client_id, okta_private_jwk, jumpcloud_api_key) VALUES ($1, $2, \
                 $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, \
                 $20, $21, $22) RETURNING ",
                provider_columns!()
            )
        };
        let mut query = sqlx::query_as::<_, Row>(statement)
            .bind(name)
            .bind(provider.kind)
            .bind(&provider.issuer)
            .bind(&provider.client_id)
            .bind(&config.client_secret)
            .bind(provider.enabled)
            .bind(&provider.display_name)
            .bind(provider.disable_password_management)
            .bind(sync.directory_sync_enabled)
            .bind(sync.directory_sync_interval)
            .bind(sync.directory_sync_user_behavior)
            .bind(sync.directory_sync_admin_behavior)
            .bind(sync.directory_sync_target)
            .bind(&sync.directory_sync_group_match)
            .bind(&sync.directory_sync_user_groups)
            .bind(sync.prefetch_users)
            .bind(&sync.admin_email)
            .bind(&sync.google_service_account_email)
            .bind(&secrets.google_service_account_key)
            .bind(&sync.okta_dirsync_client_id)
            .bind(&secrets.okta_private_jwk)
            .bind(&secrets.jumpcloud_api_key);
        if let Some(current) = &current {
            query = query.bind(current.provider.id);
        }
        let row = query.fetch_one(&mut *conn).await?;

        if let Some(current) = &current {
            let same_issuer = current.provider.issuer == provider.issuer;
            // A subject identifier is only unique within its issuer. With a new issuer, old links
            // could match the wrong person, so users link again through their verified email.
            if !same_issuer {
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
            // Directory ids belong to one directory: forget them when it changes.
            if !same_issuer || current.provider.kind != provider.kind {
                sqlx::query("DELETE FROM user_directory_identity WHERE provider_id = $1")
                    .bind(current.provider.id)
                    .execute(&mut *conn)
                    .await?;
            }
        } else {
            let unlinked =
                sqlx::query(r#"UPDATE "user" SET openid_sub = NULL WHERE openid_sub IS NOT NULL"#)
                    .execute(&mut *conn)
                    .await?;
            if unlinked.rows_affected() > 0 {
                info!(
                    "Configured a new OpenID provider; cleared {} stale links",
                    unlinked.rows_affected()
                );
            }
        }
        Ok(row.into_config().provider)
    }

    pub async fn delete(conn: &mut PgConnection) -> Result<OpenIdProvider, ProviderError> {
        let row: Option<Row> = sqlx::query_as(concat!(
            "DELETE FROM openidprovider RETURNING ",
            provider_columns!()
        ))
        .fetch_optional(&mut *conn)
        .await?;
        let provider = row
            .map(|row| row.into_config().provider)
            .ok_or(ProviderError::NotFound)?;
        let unlinked =
            sqlx::query(r#"UPDATE "user" SET openid_sub = NULL WHERE openid_sub IS NOT NULL"#)
                .execute(&mut *conn)
                .await?;
        if unlinked.rows_affected() > 0 {
            info!(
                "The OpenID provider was removed; unlinked {} users",
                unlinked.rows_affected()
            );
        }
        Ok(provider)
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
