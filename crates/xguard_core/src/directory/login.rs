//! Signing in with a directory password.
//!
//! - The directory checks the password: XGuard binds as the user on a separate connection,
//!   and only over an encrypted connection (or one on this machine).
//! - XGuard keeps no copy of a directory user's password, so a password changed or revoked in
//!   the directory takes effect at the next sign-in.
//! - A directory user who is not yet in XGuard is added on first sign-in, if they are in sync
//!   scope (a sync group, when those are set) and their account is not disabled.
//! - An existing XGuard account can use its directory password only if it is linked to the
//!   directory entry (see [`is_linked`]).

use sqlx::PgPool;
use xguard_common::db::{Id, models::User};

use super::{DirectoryClient, DirectoryError, model::DirectoryUser};
use crate::handlers::user::check_username;

/// Who the directory says signed in.
pub enum LoginOutcome {
    /// The password is right; this is the XGuard account.
    Authenticated(Box<User<Id>>),
    /// Unknown user, wrong password or out of scope.
    Rejected,
}

fn in_sync_groups(config: &super::DirectoryConfig, groups: &[String]) -> bool {
    config.sync_groups.is_empty() || groups.iter().any(|group| config.is_sync_group(group))
}

/// Whether `user` is linked to the directory: it came from there, or a sync or push recorded
/// its entry. A local account that merely shares a username with a directory entry is not, so
/// an unrelated directory user named like a local admin cannot sign in as them.
pub(super) fn is_linked(user: &User<Id>, remote: &DirectoryUser) -> bool {
    user.from_ldap
        || user
            .ldap_user_path
            .as_deref()
            .is_some_and(|path| path.eq_ignore_ascii_case(&remote.path))
}

/// Checks `password` against the directory for `username_or_email`.
///
/// `local` is the XGuard account found for the name, if any.
pub async fn authenticate(
    pool: &PgPool,
    username_or_email: &str,
    password: &str,
    local: Option<&User<Id>>,
) -> Result<LoginOutcome, DirectoryError> {
    let config = super::enabled_config()?;
    if password.is_empty() {
        return Ok(LoginOutcome::Rejected);
    }
    let mut client = DirectoryClient::connect(config.clone()).await?;
    let result = async {
        let remote = match local {
            Some(user) => client.find_user(&user.username).await?,
            None => match client.find_user(username_or_email).await? {
                Some(remote) => Some(remote),
                None if username_or_email.contains('@') => {
                    client.find_user_by_email(username_or_email).await?
                }
                None => None,
            },
        };
        let Some(remote) = remote else {
            return Ok(LoginOutcome::Rejected);
        };
        if config.sync_account_status && remote.disabled == Some(true) {
            return Ok(LoginOutcome::Rejected);
        }
        if !client.verify_password(&remote.dn, password).await? {
            return Ok(LoginOutcome::Rejected);
        }
        let groups: Vec<String> = {
            let mut names = Vec::new();
            for dn in &remote.member_of {
                if let Some(name) = super::model::rdn_value(dn, &config.group_name_attr) {
                    names.push(name);
                }
            }
            if !config.members_are_usernames() && names.is_empty() && !config.sync_groups.is_empty()
            {
                // Without memberOf, ask each sync group whether the user is a member.
                for name in &config.sync_groups {
                    if let Some(group) = client.find_group(name).await?
                        && group
                            .members
                            .iter()
                            .any(|member| member.eq_ignore_ascii_case(&remote.dn))
                    {
                        names.push(group.name);
                    }
                }
            } else if config.members_are_usernames() && !config.sync_groups.is_empty() {
                for name in &config.sync_groups {
                    if let Some(group) = client.find_group(name).await?
                        && group
                            .members
                            .iter()
                            .any(|member| member.eq_ignore_ascii_case(&remote.username))
                    {
                        names.push(group.name);
                    }
                }
            }
            names
        };
        if !in_sync_groups(&config, &groups) {
            return Ok(LoginOutcome::Rejected);
        }

        if let Some(user) = local {
            if !is_linked(user, &remote) {
                return Ok(LoginOutcome::Rejected);
            }
            return Ok(LoginOutcome::Authenticated(Box::new(user.clone())));
        }

        check_username(&remote.username).map_err(|err| DirectoryError::Refused(err.to_string()))?;
        let mut user = User::new(
            remote.username.clone(),
            None,
            remote.last_name.clone(),
            remote.first_name.clone(),
            remote.email.clone(),
            remote.phone.clone(),
        );
        user.from_ldap = true;
        user.ldap_rdn = Some(remote.rdn.clone());
        user.ldap_user_path = Some(remote.path.clone());
        let user = user.save(pool).await?;
        info!(
            "Added {} to XGuard on their first directory sign-in",
            user.username
        );
        Ok(LoginOutcome::Authenticated(Box::new(user)))
    }
    .await;
    client.close().await;
    result
}
