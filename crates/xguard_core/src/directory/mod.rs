//! XGuard directory sync for LDAP and Active Directory. New code, AGPL-3.0.
//!
//! - [`push`]: XGuard changes go to the directory as they happen (users, status, group
//!   membership, passwords).
//! - [`sync`]: a full reconcile at the configured interval (two-way sync), on demand, or as a
//!   dry run. The authoritative side wins; see [`plan`] for the rules and the safety limits.
//! - [`login`]: users can sign in with their directory password.
//!
//! The settings are the `ldap_*` fields of [`xguard_common::db::models::Settings`].

pub mod client;
pub mod config;
pub mod login;
pub mod model;
pub mod plan;
pub mod push;
pub mod sync;
#[cfg(test)]
mod tests;

use xguard_common::db::models::Settings;

pub use self::{
    client::DirectoryClient,
    config::{Authority, DirectoryConfig},
    plan::SyncPlan,
    sync::{SyncOptions, SyncReport},
};

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("The directory {0} is not configured")]
    NotConfigured(&'static str),
    #[error("Invalid directory setting: {0}")]
    Invalid(String),
    #[error("The directory integration is disabled")]
    Disabled,
    #[error("Passwords are only sent over LDAPS or StartTLS; enable one of them for this server")]
    Insecure,
    #[error("Directory error: {0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    Refused(String),
    #[error("User management error: {0}")]
    UserManagement(#[from] crate::user_management::UserManagementError),
}

/// The current settings, if the integration is turned on.
pub fn enabled_config() -> Result<DirectoryConfig, DirectoryError> {
    let settings = Settings::get_current_settings();
    if !settings.ldap_enabled {
        return Err(DirectoryError::Disabled);
    }
    DirectoryConfig::from_settings(&settings)
}

/// Connects and binds with `settings`, then reads the directory once, to check the settings
/// before they are saved. Returns how many users and groups were found.
pub async fn test_connection(settings: &Settings) -> Result<(usize, usize), DirectoryError> {
    let config = DirectoryConfig::from_settings(settings)?;
    let mut client = DirectoryClient::connect(config).await?;
    let snapshot = client.snapshot().await;
    client.close().await;
    let snapshot = snapshot?;
    Ok((snapshot.users.len(), snapshot.groups.len()))
}
