//! The directory sync settings of the external OpenID provider (stored on its row).

use rsa::{
    RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::DecodePrivateKey,
};
use serde::{Deserialize, Serialize};
use sqlx::Type;
use url::Url;

use crate::sso::provider::{ProviderError, ProviderKind};

/// The shortest interval between periodic syncs.
pub const MIN_INTERVAL_SECS: i32 = 60;
/// The longest interval between periodic syncs (a week).
pub const MAX_INTERVAL_SECS: i32 = 7 * 24 * 3600;
const DEFAULT_INTERVAL_SECS: i32 = 600;
const MAX_PATTERNS: usize = 100;
const MAX_PATTERN_CHARS: usize = 256;
const MAX_SECRET_BYTES: usize = 16 * 1024;

/// What happens to XGuard accounts whose directory account is gone (or out of scope).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "dirsync_user_behavior", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MissingUserAction {
    #[default]
    Keep,
    Disable,
    Delete,
}

/// What the sync manages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "dirsync_target", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SyncTarget {
    /// Account status and group membership.
    #[default]
    All,
    /// Account status only (and new accounts, with prefetch).
    Users,
    /// Group membership only.
    Groups,
}

impl SyncTarget {
    #[must_use]
    pub fn users(self) -> bool {
        matches!(self, Self::All | Self::Users)
    }

    #[must_use]
    pub fn groups(self) -> bool {
        matches!(self, Self::All | Self::Groups)
    }
}

/// The directory sync settings as the API shows them: secrets are never returned, only whether
/// they are set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DirectorySyncSettings {
    pub directory_sync_enabled: bool,
    /// Seconds between periodic syncs (at least 60).
    pub directory_sync_interval: i32,
    /// For accounts that are missing from the directory (or outside the user groups).
    pub directory_sync_user_behavior: MissingUserAction,
    /// The same for admins. The last active admin is never disabled or deleted.
    pub directory_sync_admin_behavior: MissingUserAction,
    pub directory_sync_target: SyncTarget,
    /// Directory groups whose membership is synced (`*` and `?` wildcards, ignoring case);
    /// empty means all groups except XGuard admin groups.
    pub directory_sync_group_match: Vec<String>,
    /// Only members of these directory groups are synced (same patterns); empty means everyone.
    pub directory_sync_user_groups: Vec<String>,
    /// Create XGuard accounts for directory users who have none yet.
    pub prefetch_users: bool,
    /// Google: the Workspace admin the service account acts as.
    pub admin_email: Option<String>,
    pub google_service_account_email: Option<String>,
    pub google_service_account_key_set: bool,
    /// Okta: the API service app used for the sync (private key JWT).
    pub okta_dirsync_client_id: Option<String>,
    pub okta_private_jwk_set: bool,
    pub jumpcloud_api_key_set: bool,
}

impl Default for DirectorySyncSettings {
    fn default() -> Self {
        Self {
            directory_sync_enabled: false,
            directory_sync_interval: DEFAULT_INTERVAL_SECS,
            directory_sync_user_behavior: MissingUserAction::Keep,
            directory_sync_admin_behavior: MissingUserAction::Keep,
            directory_sync_target: SyncTarget::All,
            directory_sync_group_match: Vec::new(),
            directory_sync_user_groups: Vec::new(),
            prefetch_users: false,
            admin_email: None,
            google_service_account_email: None,
            google_service_account_key_set: false,
            okta_dirsync_client_id: None,
            okta_private_jwk_set: false,
            jumpcloud_api_key_set: false,
        }
    }
}

/// The directory credentials, kept server-side.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DirectorySyncSecrets {
    /// The service account's private key (PEM).
    pub google_service_account_key: Option<String>,
    /// The Okta sync app's private key (a JSON Web Key).
    pub okta_private_jwk: Option<String>,
    pub jumpcloud_api_key: Option<String>,
}

impl DirectorySyncSecrets {
    pub(crate) fn mark_set(&self, settings: &mut DirectorySyncSettings) {
        settings.google_service_account_key_set = self.google_service_account_key.is_some();
        settings.okta_private_jwk_set = self.okta_private_jwk.is_some();
        settings.jumpcloud_api_key_set = self.jumpcloud_api_key.is_some();
    }
}

/// The directory sync part of a provider update. Secrets left out (or empty) are kept.
#[derive(Clone, Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct DirectorySyncInput {
    pub directory_sync_enabled: bool,
    pub directory_sync_interval: Option<i32>,
    pub directory_sync_user_behavior: MissingUserAction,
    pub directory_sync_admin_behavior: MissingUserAction,
    pub directory_sync_target: SyncTarget,
    pub directory_sync_group_match: Vec<String>,
    pub directory_sync_user_groups: Vec<String>,
    pub prefetch_users: bool,
    pub admin_email: Option<String>,
    pub google_service_account_email: Option<String>,
    /// The service account's JSON key file, or just its PEM private key.
    pub google_service_account_key: Option<String>,
    pub okta_dirsync_client_id: Option<String>,
    /// The Okta sync app's private key as a JSON Web Key (RSA).
    pub okta_private_jwk: Option<String>,
    pub jumpcloud_api_key: Option<String>,
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::Invalid(message.into())
}

fn optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn check_email(value: Option<String>, what: &str) -> Result<Option<String>, ProviderError> {
    let value = optional_text(value);
    if let Some(email) = &value {
        let valid = email.len() <= 320
            && email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
            })
            && !email.chars().any(|c| c.is_whitespace() || c.is_control());
        if !valid {
            return Err(invalid(format!("{what} is not a valid email address.")));
        }
    }
    Ok(value)
}

fn check_patterns(values: Vec<String>, what: &str) -> Result<Vec<String>, ProviderError> {
    let mut patterns: Vec<String> = Vec::new();
    for value in values {
        let value = value.trim().to_owned();
        if value.is_empty() {
            continue;
        }
        if value.chars().count() > MAX_PATTERN_CHARS || value.chars().any(char::is_control) {
            return Err(invalid(format!(
                "Each {what} entry can have up to {MAX_PATTERN_CHARS} characters."
            )));
        }
        if !patterns
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&value))
        {
            patterns.push(value);
        }
    }
    if patterns.len() > MAX_PATTERNS {
        return Err(invalid(format!("Use up to {MAX_PATTERNS} {what} entries.")));
    }
    Ok(patterns)
}

fn new_secret(value: Option<String>, what: &str) -> Result<Option<String>, ProviderError> {
    let value = optional_text(value);
    if let Some(secret) = &value
        && secret.len() > MAX_SECRET_BYTES
    {
        return Err(invalid(format!("The {what} is too long.")));
    }
    Ok(value)
}

/// Reads an RSA private key in PKCS#8 or PKCS#1 PEM form.
pub(crate) fn parse_rsa_pem(pem: &str) -> Result<RsaPrivateKey, ProviderError> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| invalid("The service account private key is not a valid RSA key."))
}

/// The PKCS#1 DER form `jsonwebtoken` signs with.
pub(crate) fn rsa_der(key: &RsaPrivateKey) -> Result<Vec<u8>, ProviderError> {
    key.to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|_| invalid("The private key could not be encoded."))
}

#[derive(Deserialize)]
struct GoogleKeyFile {
    private_key: String,
    client_email: String,
}

#[derive(Deserialize)]
pub(crate) struct RsaJwk {
    pub kty: String,
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
    pub d: Option<String>,
    pub p: Option<String>,
    pub q: Option<String>,
}

/// Reads an RSA private key from a JSON Web Key, and its key ID.
pub(crate) fn parse_rsa_jwk(jwk: &str) -> Result<(RsaPrivateKey, Option<String>), ProviderError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bad = || invalid("The Okta private key must be an RSA private key in JWK form.");
    let jwk: RsaJwk = serde_json::from_str(jwk).map_err(|_| bad())?;
    if jwk.kty != "RSA" {
        return Err(bad());
    }
    let number = |value: Option<&String>| -> Result<rsa::BigUint, ProviderError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.ok_or_else(bad)?.trim_end_matches('='))
            .map_err(|_| bad())?;
        Ok(rsa::BigUint::from_bytes_be(&bytes))
    };
    let mut primes = Vec::new();
    if jwk.p.is_some() && jwk.q.is_some() {
        primes = vec![number(jwk.p.as_ref())?, number(jwk.q.as_ref())?];
    }
    let key = RsaPrivateKey::from_components(
        number(Some(&jwk.n))?,
        number(Some(&jwk.e))?,
        number(jwk.d.as_ref())?,
        primes,
    )
    .map_err(|_| bad())?;
    key.validate().map_err(|_| bad())?;
    Ok((key, jwk.kid))
}

/// The Entra ID tenant from an issuer such as `https://login.microsoftonline.com/{tenant}/v2.0`.
pub(crate) fn microsoft_tenant(issuer: &str) -> Result<String, ProviderError> {
    let url = Url::parse(issuer).map_err(|_| invalid("The issuer URL is not valid."))?;
    let tenant = url
        .path_segments()
        .and_then(|mut segments| segments.next())
        .unwrap_or_default()
        .to_owned();
    let valid = !tenant.is_empty()
        && tenant.len() <= 128
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
        && !["common", "organizations", "consumers"].contains(&tenant.to_lowercase().as_str());
    if !valid {
        return Err(invalid(
            "Directory sync needs the tenant's own issuer, such as \
             https://login.microsoftonline.com/<tenant ID>/v2.0.",
        ));
    }
    Ok(tenant)
}

impl DirectorySyncInput {
    /// Checks the input. Secrets that are not given are kept from `stored`; secrets the provider
    /// kind does not use are dropped.
    pub fn validate(
        self,
        kind: ProviderKind,
        issuer: &str,
        stored: &DirectorySyncSecrets,
    ) -> Result<(DirectorySyncSettings, DirectorySyncSecrets), ProviderError> {
        let interval = self
            .directory_sync_interval
            .unwrap_or(DEFAULT_INTERVAL_SECS);
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&interval) {
            return Err(invalid(format!(
                "The sync interval must be between {MIN_INTERVAL_SECS} seconds and a week."
            )));
        }
        let mut settings = DirectorySyncSettings {
            directory_sync_enabled: self.directory_sync_enabled,
            directory_sync_interval: interval,
            directory_sync_user_behavior: self.directory_sync_user_behavior,
            directory_sync_admin_behavior: self.directory_sync_admin_behavior,
            directory_sync_target: self.directory_sync_target,
            directory_sync_group_match: check_patterns(
                self.directory_sync_group_match,
                "group filter",
            )?,
            directory_sync_user_groups: check_patterns(
                self.directory_sync_user_groups,
                "user group",
            )?,
            prefetch_users: self.prefetch_users,
            admin_email: None,
            google_service_account_email: None,
            google_service_account_key_set: false,
            okta_dirsync_client_id: None,
            okta_private_jwk_set: false,
            jumpcloud_api_key_set: false,
        };
        let mut secrets = DirectorySyncSecrets::default();
        match kind {
            ProviderKind::Google => {
                settings.admin_email = check_email(self.admin_email, "The admin email")?;
                settings.google_service_account_email = check_email(
                    self.google_service_account_email,
                    "The service account email",
                )?;
                match new_secret(self.google_service_account_key, "service account key")? {
                    Some(key) => {
                        let pem = if key.starts_with('{') {
                            let file: GoogleKeyFile = serde_json::from_str(&key).map_err(|_| {
                                invalid("The service account key file is not valid.")
                            })?;
                            settings.google_service_account_email =
                                check_email(Some(file.client_email), "The service account email")?;
                            file.private_key
                        } else {
                            key
                        };
                        parse_rsa_pem(&pem)?;
                        secrets.google_service_account_key = Some(pem);
                    }
                    None => {
                        secrets
                            .google_service_account_key
                            .clone_from(&stored.google_service_account_key);
                    }
                }
            }
            ProviderKind::Okta => {
                settings.okta_dirsync_client_id = optional_text(self.okta_dirsync_client_id);
                if settings
                    .okta_dirsync_client_id
                    .as_ref()
                    .is_some_and(|id| id.len() > 512)
                {
                    return Err(invalid("The Okta sync client ID is too long."));
                }
                secrets.okta_private_jwk = match new_secret(self.okta_private_jwk, "Okta key")? {
                    Some(jwk) => {
                        parse_rsa_jwk(&jwk)?;
                        Some(jwk)
                    }
                    None => stored.okta_private_jwk.clone(),
                };
            }
            ProviderKind::JumpCloud => {
                secrets.jumpcloud_api_key =
                    match new_secret(self.jumpcloud_api_key, "JumpCloud API key")? {
                        Some(key) => {
                            if key.len() > 512 || !key.chars().all(|c| c.is_ascii_graphic()) {
                                return Err(invalid("The JumpCloud API key is not valid."));
                            }
                            Some(key)
                        }
                        None => stored.jumpcloud_api_key.clone(),
                    };
            }
            ProviderKind::Microsoft | ProviderKind::Custom | ProviderKind::Zitadel => {}
        }
        secrets.mark_set(&mut settings);

        if settings.directory_sync_enabled {
            match kind {
                ProviderKind::Google => {
                    if settings.admin_email.is_none()
                        || settings.google_service_account_email.is_none()
                        || secrets.google_service_account_key.is_none()
                    {
                        return Err(invalid(
                            "Google directory sync needs the admin email and the service \
                             account key.",
                        ));
                    }
                }
                ProviderKind::Microsoft => {
                    microsoft_tenant(issuer)?;
                }
                ProviderKind::Okta => {
                    if settings.okta_dirsync_client_id.is_none()
                        || secrets.okta_private_jwk.is_none()
                    {
                        return Err(invalid(
                            "Okta directory sync needs the sync app's client ID and private key.",
                        ));
                    }
                }
                ProviderKind::JumpCloud => {
                    if secrets.jumpcloud_api_key.is_none() {
                        return Err(invalid("JumpCloud directory sync needs an API key."));
                    }
                }
                ProviderKind::Custom | ProviderKind::Zitadel => {
                    return Err(invalid(
                        "Directory sync is available for Google, Microsoft, Okta and JumpCloud.",
                    ));
                }
            }
        }
        Ok((settings, secrets))
    }
}
