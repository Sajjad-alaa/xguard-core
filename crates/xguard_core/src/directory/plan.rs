//! Works out what a sync has to change, without changing anything.
//!
//! The plan is a pure function of both sides, so a dry run shows exactly what a real run does.
//!
//! - **Scope.** Directory users are in scope when they belong to one of the sync groups (or
//!   always, when none are set). XGuard users are in scope when they are enrolled or came from
//!   the directory, and belong to a sync group when those are set. Users are matched by
//!   username, ignoring case; an account in scope on one side is matched with its counterpart
//!   even if that one is out of scope, so leaving a sync group revokes access instead of
//!   deleting the account.
//! - **Authority.** The authoritative side wins for attributes, account status and group
//!   membership, and decides what happens to accounts that exist on one side only.
//! - **Safety.**
//!   - Admins are never deleted or disabled by a sync, nor is the account XGuard binds with.
//!   - Accounts created in XGuard are never deleted because the directory lacks them.
//!   - A username taken by an out-of-scope account is reported, not overwritten.
//!   - Groups that exist only on the non-authoritative side keep their members, so a local
//!     `admin` group is never emptied by a directory without one.
//!   - Large deletions are refused unless confirmed (see [`SyncPlan::check_deletions`]).

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Serialize;
use xguard_common::db::Id;

use super::{
    client::UserAttributes,
    config::{Authority, DirectoryConfig},
    model::{DirectorySnapshot, DirectoryUser},
};

/// An XGuard user, as the plan needs it.
#[derive(Clone, Debug)]
pub struct LocalUser {
    pub id: Id,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub from_directory: bool,
    pub enrolled_or_from_directory: bool,
    pub rdn: Option<String>,
    pub path: Option<String>,
    pub groups: BTreeSet<String>,
}

impl LocalUser {
    /// How the user should look in the directory. When the RDN attribute is the username
    /// attribute, the RDN follows the username, so a rename moves the entry.
    #[must_use]
    pub fn attributes(&self, config: &DirectoryConfig) -> UserAttributes {
        let rdn = if config.rdn_attr.eq_ignore_ascii_case(&config.username_attr) {
            self.username.clone()
        } else {
            self.rdn.clone().unwrap_or_else(|| self.username.clone())
        };
        UserAttributes {
            username: self.username.clone(),
            rdn,
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            email: self.email.clone(),
            phone: self.phone.clone().filter(|phone| !phone.is_empty()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Membership {
    pub group: String,
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatusChange {
    pub username: String,
    pub active: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncPlan {
    /// Directory users to add to XGuard.
    pub create_local: Vec<String>,
    /// XGuard users whose names, email or phone change to match the directory.
    pub update_local: Vec<String>,
    pub delete_local: Vec<String>,
    pub local_status: Vec<StatusChange>,
    pub create_local_groups: Vec<String>,
    pub add_local_members: Vec<Membership>,
    pub remove_local_members: Vec<Membership>,

    /// XGuard users to add to the directory.
    pub create_remote: Vec<String>,
    pub update_remote: Vec<String>,
    pub delete_remote: Vec<String>,
    pub remote_status: Vec<StatusChange>,
    pub create_remote_groups: Vec<String>,
    pub add_remote_members: Vec<Membership>,
    pub remove_remote_members: Vec<Membership>,

    /// Accounts left alone on purpose, with the reason.
    pub skipped: Vec<String>,

    /// Directory entries and XGuard ids the apply step needs, keyed by lower-cased username.
    #[serde(skip)]
    pub remote_users: HashMap<String, DirectoryUser>,
    #[serde(skip)]
    pub local_ids: HashMap<String, Id>,
    /// Users only bookkeeping changes for: where their entry lives in the directory.
    #[serde(skip)]
    pub record_location: Vec<String>,
    #[serde(skip)]
    pub in_scope: usize,
}

/// Deletions above both of these need confirmation.
const MASS_DELETE_MIN: usize = 5;
const MASS_DELETE_SHARE_PERCENT: usize = 20;

impl SyncPlan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.create_local.is_empty()
            && self.update_local.is_empty()
            && self.delete_local.is_empty()
            && self.local_status.is_empty()
            && self.create_local_groups.is_empty()
            && self.add_local_members.is_empty()
            && self.remove_local_members.is_empty()
            && self.create_remote.is_empty()
            && self.update_remote.is_empty()
            && self.delete_remote.is_empty()
            && self.remote_status.is_empty()
            && self.create_remote_groups.is_empty()
            && self.add_remote_members.is_empty()
            && self.remove_remote_members.is_empty()
    }

    /// Refuses a plan that deletes many accounts at once (more than 5 and more than 20% of
    /// the accounts in scope), which usually means a wrong search base or sync group.
    pub fn check_deletions(&self, confirmed: bool) -> Result<(), String> {
        let deletions = self.delete_local.len() + self.delete_remote.len();
        let threshold = (self.in_scope * MASS_DELETE_SHARE_PERCENT / 100).max(MASS_DELETE_MIN);
        if deletions > threshold && !confirmed {
            return Err(format!(
                "The sync would delete {deletions} accounts. Check the settings with a dry \
                 run, then confirm the deletion."
            ));
        }
        Ok(())
    }
}

fn key(username: &str) -> String {
    username.to_lowercase()
}

fn differs(local: &LocalUser, remote: &DirectoryUser) -> bool {
    local.first_name != remote.first_name
        || (local.last_name != remote.last_name && !remote.last_name.is_empty())
        || local.email != remote.email
        || local.phone.as_deref().filter(|p| !p.is_empty()) != remote.phone.as_deref()
}

/// Computes the changes that make both sides agree.
#[must_use]
pub fn plan(
    config: &DirectoryConfig,
    local_users: &[LocalUser],
    local_groups: &BTreeSet<String>,
    remote: &DirectorySnapshot,
) -> SyncPlan {
    let directory_wins = config.authority == Authority::Directory;
    let memberships = remote.memberships(config);
    let remote_groups: HashSet<String> = remote.groups.iter().map(|g| key(&g.name)).collect();
    let local_group_keys: HashSet<String> = local_groups.iter().map(|g| key(g)).collect();
    let in_sync_groups = |groups: &BTreeSet<String>| {
        config.sync_groups.is_empty() || groups.iter().any(|g| config.is_sync_group(g))
    };
    let no_groups = BTreeSet::new();

    let mut plan = SyncPlan::default();
    let all_local: HashMap<String, &LocalUser> =
        local_users.iter().map(|u| (key(&u.username), u)).collect();
    let local: HashMap<String, &LocalUser> = local_users
        .iter()
        .filter(|u| u.enrolled_or_from_directory && in_sync_groups(&u.groups))
        .map(|u| (key(&u.username), u))
        .collect();
    let all_remote: HashMap<String, &DirectoryUser> =
        remote.users.iter().map(|u| (key(&u.username), u)).collect();
    let remote_in_scope: HashMap<String, &DirectoryUser> = remote
        .users
        .iter()
        .filter(|u| in_sync_groups(memberships.get(&key(&u.username)).unwrap_or(&no_groups)))
        .map(|u| (key(&u.username), u))
        .collect();
    plan.in_scope = local.len().max(remote_in_scope.len());
    plan.remote_users = remote
        .users
        .iter()
        .map(|u| (key(&u.username), u.clone()))
        .collect();
    plan.local_ids = local_users
        .iter()
        .map(|u| (key(&u.username), u.id))
        .collect();

    let mut created_local_groups = BTreeSet::new();
    let mut created_remote_groups = BTreeSet::new();

    let mut usernames: BTreeSet<&String> = local.keys().collect();
    usernames.extend(remote_in_scope.keys());
    for name in usernames {
        // In scope on either side is enough: an account that left the sync groups on one side
        // is still matched, so the authoritative side's membership (and access) wins.
        let local_user = local.get(name).copied().or_else(|| {
            all_local
                .get(name)
                .copied()
                .filter(|u| u.enrolled_or_from_directory)
        });
        let remote_user = remote_in_scope
            .get(name)
            .copied()
            .or_else(|| all_remote.get(name).copied());
        match (local_user, remote_user) {
            (Some(l), Some(r)) => {
                if l.rdn.as_deref() != Some(r.rdn.as_str())
                    || l.path.as_deref() != Some(r.path.as_str())
                {
                    plan.record_location.push(l.username.clone());
                }
                if directory_wins {
                    if differs(l, r) {
                        plan.update_local.push(l.username.clone());
                    }
                } else if differs(l, r) || l.attributes(config).rdn != r.rdn {
                    plan.update_remote.push(l.username.clone());
                }
                if config.sync_account_status
                    && let Some(disabled) = r.disabled
                    && l.is_active == disabled
                {
                    if !directory_wins {
                        plan.remote_status.push(StatusChange {
                            username: l.username.clone(),
                            active: l.is_active,
                        });
                    } else if l.is_admin && disabled {
                        plan.skipped
                            .push(format!("{}: admins are not disabled by a sync", l.username));
                    } else {
                        plan.local_status.push(StatusChange {
                            username: l.username.clone(),
                            active: !disabled,
                        });
                    }
                }
                let remote_member_of = memberships.get(name).unwrap_or(&no_groups);
                sync_memberships(
                    &mut plan,
                    directory_wins,
                    &l.username,
                    &l.groups,
                    remote_member_of,
                    &local_group_keys,
                    &remote_groups,
                    &mut created_local_groups,
                    &mut created_remote_groups,
                );
            }
            (None, Some(r)) => {
                if all_local.contains_key(name) {
                    plan.skipped.push(format!(
                        "{}: an XGuard account with this username exists but is not in sync \
                         scope",
                        r.username
                    ));
                } else if directory_wins {
                    plan.create_local.push(r.username.clone());
                    let remote_member_of = memberships.get(name).unwrap_or(&no_groups);
                    sync_memberships(
                        &mut plan,
                        true,
                        &r.username,
                        &no_groups,
                        remote_member_of,
                        &local_group_keys,
                        &remote_groups,
                        &mut created_local_groups,
                        &mut created_remote_groups,
                    );
                } else if r.dn.eq_ignore_ascii_case(&config.bind_dn) {
                    plan.skipped.push(format!(
                        "{}: this is the account XGuard connects with",
                        r.username
                    ));
                } else {
                    plan.delete_remote.push(r.username.clone());
                }
            }
            (Some(l), None) => {
                if !directory_wins {
                    plan.create_remote.push(l.username.clone());
                    sync_memberships(
                        &mut plan,
                        false,
                        &l.username,
                        &l.groups,
                        &no_groups,
                        &local_group_keys,
                        &remote_groups,
                        &mut created_local_groups,
                        &mut created_remote_groups,
                    );
                } else if l.is_admin {
                    plan.skipped
                        .push(format!("{}: admins are not deleted by a sync", l.username));
                } else if !l.from_directory {
                    plan.skipped.push(format!(
                        "{}: created in XGuard, so it is not deleted",
                        l.username
                    ));
                } else {
                    plan.delete_local.push(l.username.clone());
                }
            }
            (None, None) => {}
        }
    }
    plan.create_local_groups = created_local_groups.into_iter().collect();
    plan.create_remote_groups = created_remote_groups.into_iter().collect();
    plan
}

#[allow(clippy::too_many_arguments)]
fn sync_memberships(
    plan: &mut SyncPlan,
    directory_wins: bool,
    username: &str,
    local_member_of: &BTreeSet<String>,
    remote_member_of: &BTreeSet<String>,
    local_groups: &HashSet<String>,
    remote_groups: &HashSet<String>,
    created_local_groups: &mut BTreeSet<String>,
    created_remote_groups: &mut BTreeSet<String>,
) {
    let local_keys: HashSet<String> = local_member_of.iter().map(|g| key(g)).collect();
    let remote_keys: HashSet<String> = remote_member_of.iter().map(|g| key(g)).collect();
    let membership = |group: &String| Membership {
        group: group.clone(),
        username: username.to_owned(),
    };
    if directory_wins {
        for group in remote_member_of {
            if !local_keys.contains(&key(group)) {
                if !local_groups.contains(&key(group)) {
                    created_local_groups.insert(group.clone());
                }
                plan.add_local_members.push(membership(group));
            }
        }
        for group in local_member_of {
            if !remote_keys.contains(&key(group)) && remote_groups.contains(&key(group)) {
                plan.remove_local_members.push(membership(group));
            }
        }
    } else {
        for group in local_member_of {
            if !remote_keys.contains(&key(group)) {
                if !remote_groups.contains(&key(group)) {
                    created_remote_groups.insert(group.clone());
                }
                plan.add_remote_members.push(membership(group));
            }
        }
        for group in remote_member_of {
            if !local_keys.contains(&key(group)) && local_groups.contains(&key(group)) {
                plan.remove_remote_members.push(membership(group));
            }
        }
    }
}
