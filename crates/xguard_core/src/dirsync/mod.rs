//! Directory sync with the cloud identity provider users sign in with: Google Workspace,
//! Microsoft Entra ID, Okta and JumpCloud. New code, AGPL-3.0.
//!
//! The directory is the source of truth for the accounts it knows. A sync:
//! - **matches** XGuard accounts to directory users: by the directory id recorded before, then
//!   by the OpenID subject (for providers whose subject is the directory id), then by email
//!   when that is unambiguous on both sides. The match is recorded in `user_directory_identity`.
//! - **syncs account status:** a disabled or suspended directory user is disabled in XGuard; an
//!   account the sync disabled is enabled again when the directory activates it.
//! - **handles accounts missing from the directory** (or outside the user groups) as the
//!   settings say: keep, disable or delete; admins have their own setting.
//! - **syncs group membership** of the directory groups that match the group filter.
//! - **creates accounts** for directory users without one, when prefetch is on.
//!
//! See [`plan`] for the rules and safety limits, [`sync`] for how changes are applied and
//! [`worker`] for the periodic run.
//!
//! - [`settings`]: the settings, stored on the OpenID provider.
//! - [`google`], [`microsoft`], [`okta`], [`jumpcloud`]: the API clients.

pub mod google;
pub(crate) mod http;
pub mod jumpcloud;
pub mod microsoft;
pub mod okta;
pub mod plan;
pub mod settings;
pub mod sync;
#[cfg(test)]
mod tests;
pub mod worker;

use std::time::Duration;

use futures::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use url::Url;
use xguard_common::db::Id;

use self::{
    google::{GoogleClient, GoogleCredentials},
    jumpcloud::{JumpCloudClient, JumpCloudCredentials},
    microsoft::{MicrosoftClient, MicrosoftCredentials},
    okta::{OktaClient, OktaCredentials},
    settings::{
        MissingUserAction, SyncTarget, microsoft_tenant, parse_rsa_jwk, parse_rsa_pem, rsa_der,
    },
};
use crate::sso::provider::{ProviderConfig, ProviderError, ProviderKind, is_trusted_url};

/// How many group member listings run at once.
const MEMBER_CONCURRENCY: usize = 4;
/// The most group memberships one snapshot holds.
const MAX_MEMBERSHIPS: usize = 2_000_000;

#[derive(Debug, thiserror::Error)]
pub enum DirSyncError {
    #[error("{0}")]
    NotConfigured(String),
    #[error("Directory sync is turned off")]
    Disabled,
    #[error("The directory refused XGuard's credentials: {0}")]
    Auth(String),
    #[error("{what} failed with HTTP {status}: {message}")]
    Api {
        what: String,
        status: u16,
        message: String,
    },
    #[error("The directory could not be read: {0}")]
    Http(String),
    #[error("The directory sent a response larger than 16 MiB")]
    TooLarge,
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("User management error: {0}")]
    UserManagement(#[from] crate::user_management::UserManagementError),
}

impl DirSyncError {
    /// A refused token request or key check is a credentials problem.
    fn into_auth(self) -> Self {
        match self {
            Self::Api {
                what,
                status: status @ (400 | 401 | 403),
                message,
            } => Self::Auth(format!("{what}: HTTP {status}: {message}")),
            other => other,
        }
    }

    /// Whether this is XGuard's fault rather than the settings' or the directory's.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Database(_) | Self::UserManagement(_))
    }
}

pub(crate) fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Ids from a directory end up in URL paths: they must be plain.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id != "."
        && id != ".."
        && !id.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A user as the directory describes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DirectoryUser {
    pub id: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    /// False for disabled, suspended or deprovisioned accounts.
    pub active: bool,
}

/// A group, before its members are read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRef {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGroup {
    pub id: String,
    pub name: String,
    /// Directory ids of the member users (nested groups resolved).
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DirectorySnapshot {
    pub users: Vec<DirectoryUser>,
    /// Only the groups the sync needs: those matching the group filter or the user groups.
    pub groups: Vec<DirectoryGroup>,
    /// How many groups the directory has in all.
    pub total_groups: usize,
}

/// A `*` and `?` wildcard pattern, ignoring case.
#[derive(Clone, Debug)]
pub struct Pattern(Vec<char>);

impl Pattern {
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self(pattern.trim().to_lowercase().chars().collect())
    }

    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.to_lowercase().chars().collect();
        let pattern = &self.0;
        let (mut p, mut t) = (0, 0);
        let mut backtrack: Option<(usize, usize)> = None;
        while t < text.len() {
            if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
                p += 1;
                t += 1;
            } else if p < pattern.len() && pattern[p] == '*' {
                backtrack = Some((p, t));
                p += 1;
            } else if let Some((star, matched)) = backtrack {
                p = star + 1;
                t = matched + 1;
                backtrack = Some((star, matched + 1));
            } else {
                return false;
            }
        }
        pattern[p..].iter().all(|&c| c == '*')
    }
}

/// A list of patterns; empty matches nothing (callers decide what empty means).
#[derive(Clone, Debug, Default)]
pub struct Patterns(Vec<Pattern>);

impl Patterns {
    #[must_use]
    pub fn new(patterns: &[String]) -> Self {
        Self(patterns.iter().map(|p| Pattern::new(p)).collect())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn any(&self, text: &str) -> bool {
        self.0.iter().any(|pattern| pattern.matches(text))
    }
}

pub enum Credentials {
    Google(GoogleCredentials),
    Microsoft(MicrosoftCredentials),
    Okta(OktaCredentials),
    JumpCloud(JumpCloudCredentials),
}

/// Everything a sync needs, checked.
pub struct SyncConfig {
    pub provider_id: Id,
    /// The name activity log entries use.
    pub provider_name: String,
    pub kind: ProviderKind,
    pub enabled: bool,
    pub interval: Duration,
    pub target: SyncTarget,
    pub user_behavior: MissingUserAction,
    pub admin_behavior: MissingUserAction,
    pub prefetch_users: bool,
    /// Directory groups whose membership is synced; empty means all but admin groups.
    pub group_match: Patterns,
    /// Only members of these groups are synced; empty means everyone.
    pub user_groups: Patterns,
    pub credentials: Credentials,
}

fn base(url: &str) -> Url {
    Url::parse(url).expect("a valid built-in URL")
}

impl SyncConfig {
    /// Builds the sync settings of `config`, whether or not the sync is turned on.
    pub fn from_provider(config: &ProviderConfig) -> Result<Self, DirSyncError> {
        let provider = &config.provider;
        let sync = &provider.directory_sync;
        let secrets = &config.directory_secrets;
        let missing =
            |what: &str| DirSyncError::NotConfigured(format!("Directory sync needs {what}."));
        let credentials = match provider.kind {
            ProviderKind::Google => {
                let key = secrets
                    .google_service_account_key
                    .as_deref()
                    .ok_or_else(|| missing("the Google service account key"))?;
                Credentials::Google(GoogleCredentials {
                    service_account_email: sync
                        .google_service_account_email
                        .clone()
                        .ok_or_else(|| missing("the Google service account email"))?,
                    private_key: rsa_der(&parse_rsa_pem(key)?)?,
                    admin_email: sync
                        .admin_email
                        .clone()
                        .ok_or_else(|| missing("the Google Workspace admin email"))?,
                    token_url: base(google::TOKEN_URL),
                    api_base: base(google::API_BASE),
                })
            }
            ProviderKind::Microsoft => Credentials::Microsoft(MicrosoftCredentials {
                tenant: microsoft_tenant(&provider.issuer)?,
                client_id: provider.client_id.clone(),
                client_secret: config.client_secret.clone(),
                login_base: base(microsoft::LOGIN_BASE),
                graph_base: base(microsoft::GRAPH_BASE),
            }),
            ProviderKind::Okta => {
                let issuer =
                    Url::parse(&provider.issuer).map_err(|_| missing("a valid issuer URL"))?;
                if !is_trusted_url(&issuer) {
                    return Err(missing("an https:// issuer"));
                }
                let (key, key_id) = parse_rsa_jwk(
                    secrets
                        .okta_private_jwk
                        .as_deref()
                        .ok_or_else(|| missing("the Okta sync app's private key"))?,
                )?;
                Credentials::Okta(OktaCredentials {
                    base: okta::org_base(&issuer),
                    client_id: sync
                        .okta_dirsync_client_id
                        .clone()
                        .ok_or_else(|| missing("the Okta sync app's client ID"))?,
                    private_key: rsa_der(&key)?,
                    key_id,
                })
            }
            ProviderKind::JumpCloud => Credentials::JumpCloud(JumpCloudCredentials {
                api_key: secrets
                    .jumpcloud_api_key
                    .clone()
                    .ok_or_else(|| missing("a JumpCloud API key"))?,
                base: base(jumpcloud::api_base_for(&provider.issuer)),
            }),
            ProviderKind::Custom | ProviderKind::Zitadel => {
                return Err(DirSyncError::NotConfigured(
                    "Directory sync is available for Google, Microsoft, Okta and JumpCloud.".into(),
                ));
            }
        };
        Ok(Self {
            provider_id: provider.id,
            provider_name: provider.label(),
            kind: provider.kind,
            enabled: sync.directory_sync_enabled,
            interval: Duration::from_secs(
                u64::try_from(
                    sync.directory_sync_interval
                        .max(settings::MIN_INTERVAL_SECS),
                )
                .unwrap_or(600),
            ),
            target: sync.directory_sync_target,
            user_behavior: sync.directory_sync_user_behavior,
            admin_behavior: sync.directory_sync_admin_behavior,
            prefetch_users: sync.prefetch_users,
            group_match: Patterns::new(&sync.directory_sync_group_match),
            user_groups: Patterns::new(&sync.directory_sync_user_groups),
            credentials,
        })
    }

    /// Whether the OpenID subject of this provider is the directory's user id, so sign-in links
    /// can be matched to directory users.
    #[must_use]
    pub fn subject_is_directory_id(&self) -> bool {
        matches!(self.kind, ProviderKind::Google | ProviderKind::Okta)
    }

    /// Whether the membership of `group` is synced.
    #[must_use]
    pub fn syncs_group(&self, group: &str) -> bool {
        self.target.groups() && (self.group_match.is_empty() || self.group_match.any(group))
    }
}

/// A signed-in directory API client.
pub enum DirectoryApi {
    Google(GoogleClient),
    Microsoft(MicrosoftClient),
    Okta(OktaClient),
    JumpCloud(JumpCloudClient),
}

impl DirectoryApi {
    /// Signs in to the directory (gets an access token, or checks the API key).
    pub async fn connect(config: &SyncConfig) -> Result<Self, DirSyncError> {
        let http = http::client()?;
        Ok(match &config.credentials {
            Credentials::Google(credentials) => {
                Self::Google(GoogleClient::connect(http, credentials).await?)
            }
            Credentials::Microsoft(credentials) => {
                Self::Microsoft(MicrosoftClient::connect(http, credentials).await?)
            }
            Credentials::Okta(credentials) => {
                Self::Okta(OktaClient::connect(http, credentials).await?)
            }
            Credentials::JumpCloud(credentials) => {
                let client = JumpCloudClient::new(http, credentials);
                client.check().await?;
                Self::JumpCloud(client)
            }
        })
    }

    pub async fn users(&self) -> Result<Vec<DirectoryUser>, DirSyncError> {
        match self {
            Self::Google(client) => client.users().await,
            Self::Microsoft(client) => client.users().await,
            Self::Okta(client) => client.users().await,
            Self::JumpCloud(client) => client.users().await,
        }
    }

    pub async fn groups(&self) -> Result<Vec<GroupRef>, DirSyncError> {
        match self {
            Self::Google(client) => client.groups().await,
            Self::Microsoft(client) => client.groups().await,
            Self::Okta(client) => client.groups().await,
            Self::JumpCloud(client) => client.groups().await,
        }
    }

    pub async fn members(&self, group: &GroupRef) -> Result<Vec<String>, DirSyncError> {
        match self {
            Self::Google(client) => client.members(group).await,
            Self::Microsoft(client) => client.members(group).await,
            Self::Okta(client) => client.members(group).await,
            Self::JumpCloud(client) => client.members(group).await,
        }
    }

    /// Reads what the sync needs: all users, and the members of the groups it syncs or scopes
    /// users by. A failed read fails the whole snapshot, so a sync never acts on partial data.
    pub async fn snapshot(&self, config: &SyncConfig) -> Result<DirectorySnapshot, DirSyncError> {
        let users = self.users().await?;
        let needs_groups = config.target.groups() || !config.user_groups.is_empty();
        if !needs_groups {
            return Ok(DirectorySnapshot {
                users,
                groups: Vec::new(),
                total_groups: 0,
            });
        }
        let all_groups = self.groups().await?;
        let total_groups = all_groups.len();
        let wanted: Vec<GroupRef> = all_groups
            .into_iter()
            .filter(|group| config.syncs_group(&group.name) || config.user_groups.any(&group.name))
            .collect();
        let members: Vec<Vec<String>> = stream::iter(wanted.clone())
            .map(|group| async move { self.members(&group).await })
            .buffered(MEMBER_CONCURRENCY)
            .try_collect()
            .await?;
        if members.iter().map(Vec::len).sum::<usize>() > MAX_MEMBERSHIPS {
            return Err(DirSyncError::Http(format!(
                "the directory has more than {MAX_MEMBERSHIPS} group memberships"
            )));
        }
        let groups = wanted
            .into_iter()
            .zip(members)
            .map(|(group, members)| DirectoryGroup {
                id: group.id,
                name: group.name,
                members,
            })
            .collect();
        Ok(DirectorySnapshot {
            users,
            groups,
            total_groups,
        })
    }
}

/// What a connection test found.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectionTest {
    pub users: usize,
    pub groups: usize,
}

/// Signs in to the directory and lists its users and groups once.
pub async fn test_connection(config: &SyncConfig) -> Result<ConnectionTest, DirSyncError> {
    let api = DirectoryApi::connect(config).await?;
    let users = api.users().await?.len();
    let groups = api.groups().await?.len();
    Ok(ConnectionTest { users, groups })
}
