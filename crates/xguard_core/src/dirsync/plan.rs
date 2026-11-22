//! Works out what a sync has to change, without changing anything.
//!
//! The plan is a pure function of the directory snapshot and XGuard's accounts, so a dry run
//! shows exactly what a real run does.
//!
//! - **Matching.** A directory user matches the XGuard account recorded for their directory id;
//!   else (Google, Okta) the account signed in with that id as OpenID subject; else the one
//!   account with the same email, when exactly one directory user has that email and the
//!   account is not linked to someone else. Every new match is recorded.
//! - **Scope.** Directory users are in scope when they belong to one of the user groups (or
//!   always, when none are set). XGuard accounts are synced only when they are linked to the
//!   provider (matched before, or signed in through it); accounts created in XGuard and never
//!   linked are left alone.
//! - **Status** (targets `all` and `users`). Disabled directory users are disabled; accounts the
//!   sync disabled are enabled again when the directory activates them. Linked accounts missing
//!   from the directory or out of scope are kept, disabled or deleted as the user (or admin)
//!   setting says.
//! - **Groups** (targets `all` and `groups`). Membership of the directory groups matching the
//!   group filter follows the directory; missing XGuard groups are created. XGuard groups with
//!   no counterpart in the filter are never touched.
//! - **Safety.**
//!   - The last active admin is never disabled, deleted or removed from the admin groups.
//!   - Admin groups are synced only when the group filter names them; an empty filter (all
//!     groups) skips them, so a directory group cannot grant XGuard admin rights by accident.
//!   - Disabling or deleting many accounts at once, or any at all when the directory returned
//!     no users in scope, needs confirmation (see [`SyncPlan::check_revocations`]).
//!   - An account the admin disabled is never enabled by the sync.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Serialize;
use xguard_common::db::Id;

use super::{DirectorySnapshot, DirectoryUser, SyncConfig, settings::MissingUserAction};
use crate::{handlers::user::check_username, sso::username_base};

/// An XGuard account, as the plan needs it.
#[derive(Clone, Debug)]
pub struct LocalUser {
    pub id: Id,
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub is_admin: bool,
    pub openid_sub: Option<String>,
    /// The directory id recorded for this provider.
    pub external_id: Option<String>,
    /// The sync disabled this account.
    pub sync_disabled: bool,
    pub groups: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct LocalGroup {
    pub name: String,
    pub is_admin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    pub username: String,
    pub external_id: String,
    #[serde(skip)]
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub external_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileChange {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    #[serde(skip)]
    pub user_id: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountChange {
    pub username: String,
    pub reason: String,
    #[serde(skip)]
    pub user_id: Id,
    /// Counts towards the mass revocation check (missing from the directory).
    #[serde(skip)]
    pub missing: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Membership {
    pub group: String,
    pub username: String,
    /// None for accounts the sync creates.
    #[serde(skip)]
    pub user_id: Option<Id>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct PlanStats {
    pub directory_users: usize,
    pub directory_users_in_scope: usize,
    pub directory_groups: usize,
    pub synced_groups: usize,
    pub matched_users: usize,
    pub linked_users: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncPlan {
    /// Matches to record (directory id of an XGuard account).
    pub link_users: Vec<Link>,
    pub create_users: Vec<NewUser>,
    pub update_users: Vec<ProfileChange>,
    pub enable_users: Vec<AccountChange>,
    pub disable_users: Vec<AccountChange>,
    pub delete_users: Vec<AccountChange>,
    pub create_groups: Vec<String>,
    pub add_members: Vec<Membership>,
    pub remove_members: Vec<Membership>,
    /// What was left alone on purpose, and why.
    pub skipped: Vec<String>,
    pub stats: PlanStats,
}

/// Revocations above both of these need confirmation.
const MASS_REVOKE_MIN: usize = 5;
const MASS_REVOKE_SHARE_PERCENT: usize = 20;
const MAX_GROUP_NAME_CHARS: usize = 128;

impl SyncPlan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.link_users.is_empty()
            && self.create_users.is_empty()
            && self.update_users.is_empty()
            && self.enable_users.is_empty()
            && self.disable_users.is_empty()
            && self.delete_users.is_empty()
            && self.create_groups.is_empty()
            && self.add_members.is_empty()
            && self.remove_members.is_empty()
    }

    /// Accounts disabled or deleted because the directory lacks them.
    #[must_use]
    pub fn revocations(&self) -> usize {
        self.disable_users.iter().filter(|c| c.missing).count() + self.delete_users.len()
    }

    /// Refuses a plan that disables or deletes many accounts because the directory lacks them
    /// (more than 5 and more than 20% of the linked accounts), or any when the directory
    /// returned nobody in scope. Both usually mean a wrong setting or a bad directory read.
    pub fn check_revocations(&self, confirmed: bool) -> Result<(), String> {
        let revocations = self.revocations();
        if confirmed || revocations == 0 {
            return Ok(());
        }
        if self.stats.directory_users_in_scope == 0 {
            return Err(format!(
                "The directory returned no users in scope, so the sync would disable or delete \
                 {revocations} accounts. Check the settings with a dry run, then confirm."
            ));
        }
        let threshold =
            (self.stats.linked_users * MASS_REVOKE_SHARE_PERCENT / 100).max(MASS_REVOKE_MIN);
        if revocations > threshold {
            return Err(format!(
                "The sync would disable or delete {revocations} accounts. Check the settings \
                 with a dry run, then confirm."
            ));
        }
        Ok(())
    }
}

fn key(text: &str) -> String {
    text.to_lowercase()
}

/// Group names XGuard accepts from a directory.
fn usable_group_name(name: &str) -> bool {
    name.chars().count() <= MAX_GROUP_NAME_CHARS && xguard_common::names::is_safe_name(name)
}

/// Keeps one active admin: returns false (and changes nothing) when `user` is the last one.
fn take_admin(active_admins: &mut usize, user: &LocalUser) -> bool {
    if !(user.is_admin && user.is_active) {
        return true;
    }
    if *active_admins <= 1 {
        return false;
    }
    *active_admins -= 1;
    true
}

/// A free username for a new account, derived from the email.
fn new_username(email: &str, taken: &HashSet<String>) -> Option<String> {
    let base = username_base(email)?;
    (0..100)
        .map(|n| {
            if n == 0 {
                base.clone()
            } else {
                format!("{base}-{n}")
            }
        })
        .find(|candidate| check_username(candidate).is_ok() && !taken.contains(&key(candidate)))
}

/// Computes the changes that bring XGuard in line with the directory.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn plan(
    config: &SyncConfig,
    local_users: &[LocalUser],
    local_groups: &[LocalGroup],
    snapshot: &DirectorySnapshot,
) -> SyncPlan {
    let mut plan = SyncPlan::default();
    let mut users: Vec<&LocalUser> = local_users.iter().collect();
    users.sort_by(|a, b| a.username.cmp(&b.username));
    let mut directory: Vec<&DirectoryUser> = snapshot.users.iter().collect();
    directory.sort_by(|a, b| a.id.cmp(&b.id));

    // Who is in scope.
    let scope_members: Option<HashSet<&str>> = (!config.user_groups.is_empty()).then(|| {
        snapshot
            .groups
            .iter()
            .filter(|group| config.user_groups.any(&group.name))
            .flat_map(|group| group.members.iter().map(String::as_str))
            .collect()
    });
    let in_scope = |d: &DirectoryUser| {
        scope_members
            .as_ref()
            .is_none_or(|members| members.contains(d.id.as_str()))
    };

    // Matching.
    let by_external: HashMap<&str, &LocalUser> = users
        .iter()
        .filter_map(|u| u.external_id.as_deref().map(|id| (id, *u)))
        .collect();
    let by_subject: HashMap<&str, &LocalUser> = users
        .iter()
        .filter_map(|u| u.openid_sub.as_deref().map(|sub| (sub, *u)))
        .collect();
    let mut by_email: HashMap<String, Vec<&LocalUser>> = HashMap::new();
    for user in &users {
        by_email.entry(key(&user.email)).or_default().push(user);
    }
    let mut directory_emails: HashMap<String, usize> = HashMap::new();
    for d in &directory {
        if let Some(email) = &d.email {
            *directory_emails.entry(key(email)).or_default() += 1;
        }
    }
    let subject_is_id = config.subject_is_directory_id();

    let mut matched: BTreeMap<String, (&LocalUser, &DirectoryUser)> = BTreeMap::new();
    let mut matched_ids: HashSet<Id> = HashSet::new();
    let mut unmatched: Vec<&DirectoryUser> = Vec::new();
    for d in &directory {
        let mut found = by_external.get(d.id.as_str()).copied();
        if found.is_none() && subject_is_id {
            found = by_subject
                .get(d.id.as_str())
                .copied()
                .filter(|u| u.external_id.is_none());
        }
        if found.is_none()
            && let Some(email) = d.email.as_deref()
        {
            let candidates = by_email.get(&key(email)).map_or(&[][..], Vec::as_slice);
            if let [candidate] = candidates {
                let unique_in_directory = directory_emails.get(&key(email)) == Some(&1);
                // Any stored directory external_id or subject belonging to another directory ID
                // must never be silently reassigned on email match.
                let linked_elsewhere = candidate
                    .external_id
                    .as_deref()
                    .is_some_and(|id| id != d.id);
                let other_subject = subject_is_id
                    && candidate
                        .openid_sub
                        .as_deref()
                        .is_some_and(|sub| sub != d.id);
                let out_of_scope_unlinked = candidate.external_id.is_none()
                    && candidate.openid_sub.is_none()
                    && !in_scope(d);
                if out_of_scope_unlinked {
                    // Leave unlinked local accounts untouched when the directory user is outside
                    // the configured `user_groups`.
                } else if !unique_in_directory {
                    plan.skipped.push(format!(
                        "{email}: several directory users have this email, so it is not linked \
                         to {}",
                        candidate.username
                    ));
                } else if linked_elsewhere || other_subject {
                    plan.skipped.push(format!(
                        "{email}: {} is linked to another directory user",
                        candidate.username
                    ));
                } else {
                    found = Some(candidate);
                }
            } else if candidates.len() > 1 {
                plan.skipped.push(format!(
                    "{email}: several XGuard accounts have this email, so none is linked"
                ));
            }
        }
        match found {
            Some(user) if matched_ids.insert(user.id) => {
                if user.external_id.as_deref() != Some(d.id.as_str()) {
                    plan.link_users.push(Link {
                        username: user.username.clone(),
                        external_id: d.id.clone(),
                        user_id: user.id,
                    });
                }
                matched.insert(user.username.clone(), (user, d));
            }
            Some(user) => plan.skipped.push(format!(
                "{}: matches several directory users; only the first is linked",
                user.username
            )),
            None => unmatched.push(d),
        }
    }
    plan.stats = PlanStats {
        directory_users: directory.len(),
        directory_users_in_scope: directory.iter().filter(|d| in_scope(d)).count(),
        directory_groups: snapshot.total_groups,
        synced_groups: 0,
        matched_users: matched.len(),
        linked_users: users
            .iter()
            .filter(|u| {
                matched_ids.contains(&u.id) || u.external_id.is_some() || u.openid_sub.is_some()
            })
            .count(),
    };

    let mut active_admins = users.iter().filter(|u| u.is_admin && u.is_active).count();
    let behavior = |user: &LocalUser| {
        if user.is_admin {
            config.admin_behavior
        } else {
            config.user_behavior
        }
    };

    if config.target.users() {
        // Status and profile of matched accounts.
        let mut emails_in_use: HashMap<String, Id> =
            users.iter().map(|u| (key(&u.email), u.id)).collect();
        for (user, d) in matched.values() {
            if !in_scope(d) {
                continue;
            }
            let first_name = d.first_name.clone().filter(|n| !n.trim().is_empty());
            let last_name = d.last_name.clone().filter(|n| !n.trim().is_empty());
            let email = d.email.clone().filter(|e| !e.trim().is_empty());
            let new_first = first_name.unwrap_or_else(|| user.first_name.clone());
            let new_last = last_name.unwrap_or_else(|| user.last_name.clone());
            let mut new_email = email.unwrap_or_else(|| user.email.clone());
            if !new_email.eq_ignore_ascii_case(&user.email) {
                match emails_in_use.get(&key(&new_email)) {
                    Some(owner) if *owner != user.id => {
                        plan.skipped.push(format!(
                            "{}: the directory email {new_email} is used by another XGuard \
                             account",
                            user.username
                        ));
                        new_email.clone_from(&user.email);
                    }
                    _ => {
                        emails_in_use.remove(&key(&user.email));
                        emails_in_use.insert(key(&new_email), user.id);
                    }
                }
            }
            if new_first != user.first_name || new_last != user.last_name || new_email != user.email
            {
                plan.update_users.push(ProfileChange {
                    username: user.username.clone(),
                    first_name: new_first,
                    last_name: new_last,
                    email: new_email,
                    user_id: user.id,
                });
            }

            if !d.active && user.is_active {
                if user.is_admin && config.admin_behavior == MissingUserAction::Keep {
                    plan.skipped.push(format!(
                        "{}: disabled in the directory, but admins are kept",
                        user.username
                    ));
                } else if !take_admin(&mut active_admins, user) {
                    plan.skipped.push(format!(
                        "{}: disabled in the directory, but this is the last active admin",
                        user.username
                    ));
                } else {
                    plan.disable_users.push(AccountChange {
                        username: user.username.clone(),
                        reason: "disabled in the directory".into(),
                        user_id: user.id,
                        missing: false,
                    });
                }
            } else if d.active && !user.is_active {
                if user.sync_disabled {
                    plan.enable_users.push(AccountChange {
                        username: user.username.clone(),
                        reason: "active in the directory".into(),
                        user_id: user.id,
                        missing: false,
                    });
                } else {
                    plan.skipped.push(format!(
                        "{}: active in the directory, but disabled in XGuard by an admin",
                        user.username
                    ));
                }
            }
        }

        // Linked accounts the directory lacks (or has out of scope).
        for user in &users {
            let reason = match matched.get(&user.username) {
                Some((_, d)) if in_scope(d) => continue,
                Some(_) => "outside the user groups",
                None if user.external_id.is_some() || user.openid_sub.is_some() => {
                    "missing from the directory"
                }
                None => continue,
            };
            let change = || AccountChange {
                username: user.username.clone(),
                reason: reason.into(),
                user_id: user.id,
                missing: true,
            };
            match behavior(user) {
                MissingUserAction::Keep => {}
                MissingUserAction::Disable if !user.is_active => {}
                action => {
                    if !take_admin(&mut active_admins, user) {
                        plan.skipped.push(format!(
                            "{}: {reason}, but this is the last active admin",
                            user.username
                        ));
                    } else if action == MissingUserAction::Delete {
                        plan.delete_users.push(change());
                    } else {
                        plan.disable_users.push(change());
                    }
                }
            }
        }
    }

    // New accounts.
    let mut new_users: Vec<(String, &DirectoryUser)> = Vec::new();
    if config.target.users() && config.prefetch_users {
        let mut taken: HashSet<String> = users.iter().map(|u| key(&u.username)).collect();
        for d in &unmatched {
            if !d.active || !in_scope(d) {
                continue;
            }
            let Some(email) = d.email.as_deref().filter(|e| e.contains('@')) else {
                plan.skipped.push(format!(
                    "directory user {}: no email, so no account is created",
                    d.id
                ));
                continue;
            };
            if by_email.contains_key(&key(email)) || directory_emails.get(&key(email)) != Some(&1) {
                // Reported by the matching above.
                continue;
            }
            let Some(username) = new_username(email, &taken) else {
                plan.skipped
                    .push(format!("{email}: no free username for a new account"));
                continue;
            };
            taken.insert(key(&username));
            plan.create_users.push(NewUser {
                username: username.clone(),
                email: email.to_owned(),
                first_name: d.first_name.clone().unwrap_or_default(),
                last_name: d.last_name.clone().unwrap_or_else(|| username.clone()),
                phone: d.phone.clone(),
                external_id: d.id.clone(),
            });
        }
        let by_id: HashMap<&str, &DirectoryUser> =
            unmatched.iter().map(|d| (d.id.as_str(), *d)).collect();
        new_users = plan
            .create_users
            .iter()
            .filter_map(|new| {
                by_id
                    .get(new.external_id.as_str())
                    .map(|d| (new.username.clone(), *d))
            })
            .collect();
    }

    // Group membership.
    if config.target.groups() {
        let local_by_key: HashMap<String, &LocalGroup> =
            local_groups.iter().map(|g| (key(&g.name), g)).collect();
        // Synced groups by lower-cased name: the name to use and the member ids. Directory
        // groups with the same name are merged.
        let mut synced: BTreeMap<String, (String, HashSet<&str>)> = BTreeMap::new();
        let mut skipped_admin = BTreeSet::new();
        for group in &snapshot.groups {
            if !config.syncs_group(&group.name) {
                continue;
            }
            if !usable_group_name(&group.name) {
                plan.skipped.push(format!(
                    "group {}: XGuard group names use letters, digits, spaces and - _ . ( ) : /",
                    group.name
                ));
                continue;
            }
            let name_key = key(&group.name);
            let is_admin = local_by_key.get(&name_key).is_some_and(|g| g.is_admin);
            if is_admin && config.group_match.is_empty() {
                skipped_admin.insert(group.name.clone());
                continue;
            }
            let entry = synced
                .entry(name_key)
                .or_insert_with(|| (group.name.clone(), HashSet::new()));
            entry.1.extend(group.members.iter().map(String::as_str));
        }
        for name in skipped_admin {
            plan.skipped.push(format!(
                "group {name}: an XGuard admin group is only synced when the group filter \
                 names it"
            ));
        }
        plan.stats.synced_groups = synced.len();
        let desired = |d: &DirectoryUser| -> BTreeSet<&String> {
            synced
                .iter()
                .filter(|(_, (_, members))| members.contains(d.id.as_str()))
                .map(|(name_key, _)| name_key)
                .collect()
        };
        let mut create_groups = BTreeSet::new();
        let mut add = |plan: &mut SyncPlan, name_key: &String, username: &str, user_id| {
            let (name, _) = &synced[name_key];
            let group = match local_by_key.get(name_key) {
                Some(local) => local.name.clone(),
                None => {
                    create_groups.insert(name.clone());
                    name.clone()
                }
            };
            plan.add_members.push(Membership {
                group,
                username: username.to_owned(),
                user_id,
            });
        };

        let is_admin_group = |name: &str| local_by_key.get(&key(name)).is_some_and(|g| g.is_admin);
        let in_scope_matched: Vec<(&LocalUser, &DirectoryUser)> = matched
            .values()
            .filter(|(_, d)| in_scope(d))
            .copied()
            .collect();

        let disabled_ids: HashSet<Id> = plan.disable_users.iter().map(|c| c.user_id).collect();
        let enabled_ids: HashSet<Id> = plan.enable_users.iter().map(|c| c.user_id).collect();
        // Additions first: someone who joins an admin group keeps an admin around, so others
        // may then leave it.
        for (user, d) in &in_scope_matched {
            let mut becomes_admin = false;
            for name_key in desired(d) {
                if !user.groups.iter().any(|g| &key(g) == name_key) {
                    becomes_admin |= is_admin_group(name_key);
                    add(&mut plan, name_key, &user.username, Some(user.id));
                }
            }
            let will_be_active = (user.is_active && !disabled_ids.contains(&user.id))
                || enabled_ids.contains(&user.id);
            if becomes_admin && will_be_active && !user.is_admin {
                active_admins += 1;
            }
        }
        for (username, d) in &new_users {
            let mut becomes_admin = false;
            for name_key in desired(d) {
                becomes_admin |= is_admin_group(name_key);
                add(&mut plan, name_key, username, None);
            }
            if becomes_admin {
                active_admins += 1;
            }
        }

        for (user, d) in &in_scope_matched {
            let want = desired(d);
            let removals: Vec<&String> = user
                .groups
                .iter()
                .filter(|g| synced.contains_key(&key(g)) && !want.contains(&&key(g)))
                .collect();
            // Whether the user stays an admin after these removals.
            let keeps_admin = user
                .groups
                .iter()
                .any(|g| is_admin_group(g) && !removals.contains(&g));
            let admin_ok =
                !(user.is_admin && !keeps_admin && removals.iter().any(|g| is_admin_group(g)))
                    || take_admin(&mut active_admins, user);
            for group in removals {
                if is_admin_group(group) && !admin_ok {
                    plan.skipped.push(format!(
                        "{}: not removed from admin group {group}, this is the last active admin",
                        user.username
                    ));
                    continue;
                }
                plan.remove_members.push(Membership {
                    group: group.clone(),
                    username: user.username.clone(),
                    user_id: Some(user.id),
                });
            }
        }
        plan.create_groups = create_groups.into_iter().collect();
    }
    plan
}
