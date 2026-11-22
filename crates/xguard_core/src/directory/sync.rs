//! A full reconcile between XGuard and the directory.
//!
//! - **Reading:** one paged read of the directory and three queries on the XGuard side.
//! - **Local changes:** each account is applied in its own savepoint, so one bad entry (an
//!   invalid username, a duplicate email) is reported without blocking the rest. Gateways are
//!   updated once per touched user, after commit.
//! - **Status:** the sync status setting is `in sync` only after a run without errors.

use std::collections::{BTreeSet, HashMap, HashSet};

use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use tokio::sync::mpsc::UnboundedSender;
use xguard_common::db::{
    Id,
    models::{
        Settings, User,
        group::Group,
        settings::{LdapSyncStatus, update_current_settings},
    },
};

use super::{
    DirectoryClient, DirectoryConfig, DirectoryError,
    model::{DirectoryGroup, DirectorySnapshot, DirectoryUser},
    plan::{LocalUser, SyncPlan, plan},
};
use crate::{
    events::LdapSyncEventType, grpc::GatewayCommand, handlers::user::check_username,
    user_management::UserManager,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct SyncOptions {
    /// Compute the plan without changing anything.
    pub dry_run: bool,
    /// Allow a run that deletes many accounts (see [`SyncPlan::check_deletions`]).
    pub confirm_deletions: bool,
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub plan: SyncPlan,
    pub applied: bool,
    pub errors: Vec<String>,
}

fn key(name: &str) -> String {
    name.to_lowercase()
}

/// XGuard users with their groups, and all group names.
pub async fn load_local(pool: &PgPool) -> Result<(Vec<LocalUser>, BTreeSet<String>), sqlx::Error> {
    let users = User::all(pool).await?;
    let memberships: Vec<(Id, String, bool)> = sqlx::query_as(
        r#"SELECT gu.user_id, g.name, g.is_admin FROM group_user gu JOIN "group" g ON g.id = gu.group_id"#,
    )
    .fetch_all(pool)
    .await?;
    let groups: BTreeSet<String> = sqlx::query_scalar(r#"SELECT name FROM "group""#)
        .fetch_all(pool)
        .await?
        .into_iter()
        .collect();
    let mut by_user: HashMap<Id, (BTreeSet<String>, bool)> = HashMap::new();
    for (user_id, group, is_admin) in memberships {
        let entry = by_user.entry(user_id).or_default();
        entry.0.insert(group);
        entry.1 |= is_admin;
    }
    let local = users
        .into_iter()
        .map(|user| {
            let (groups, is_admin) = by_user.remove(&user.id).unwrap_or_default();
            LocalUser {
                id: user.id,
                enrolled_or_from_directory: user.is_enrolled_or_from_ldap(),
                username: user.username,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
                phone: user.phone,
                is_active: user.is_active,
                is_admin,
                from_directory: user.from_ldap,
                rdn: user.ldap_rdn,
                path: user.ldap_user_path,
                groups,
            }
        })
        .collect();
    Ok((local, groups))
}

/// A password nobody knows, for directory accounts XGuard creates without one. The real
/// password is written the next time the user signs in to XGuard or changes it.
pub(super) fn random_password() -> String {
    let body: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    // Satisfy common complexity rules (Active Directory requires three character classes).
    format!("{body}#9aA")
}

/// One sync at a time: the periodic run and an admin's "sync now" never overlap.
static RUN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reads both sides, plans and (unless it is a dry run) applies the changes.
pub async fn run(
    pool: &PgPool,
    config: DirectoryConfig,
    options: SyncOptions,
    events: &UnboundedSender<LdapSyncEventType>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<SyncReport, DirectoryError> {
    let _guard = RUN_LOCK.lock().await;
    let mut client = DirectoryClient::connect(config.clone()).await?;
    let result = run_with(&mut client, pool, options, events, gateway_tx).await;
    client.close().await;
    if !options.dry_run {
        let in_sync = result.as_ref().is_ok_and(|report| report.errors.is_empty());
        set_sync_status(pool, in_sync).await;
    }
    result
}

async fn run_with(
    client: &mut DirectoryClient,
    pool: &PgPool,
    options: SyncOptions,
    events: &UnboundedSender<LdapSyncEventType>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<SyncReport, DirectoryError> {
    let snapshot = client.snapshot().await?;
    let (local, groups) = load_local(pool).await?;
    let plan = plan(&client.config, &local, &groups, &snapshot);
    if options.dry_run {
        return Ok(SyncReport {
            plan,
            applied: false,
            errors: Vec::new(),
        });
    }
    plan.check_deletions(options.confirm_deletions)
        .map_err(DirectoryError::Refused)?;
    let mut errors = apply_local(pool, &client.config, &plan, events, gateway_tx).await?;
    errors.extend(apply_remote(client, pool, &plan, &local, &snapshot, events).await);
    if !plan.is_empty() {
        info!(
            "Directory sync applied: {} created, {} updated, {} deleted in XGuard; {} created, \
             {} updated, {} deleted in the directory; {} errors",
            plan.create_local.len(),
            plan.update_local.len(),
            plan.delete_local.len(),
            plan.create_remote.len(),
            plan.update_remote.len(),
            plan.delete_remote.len(),
            errors.len()
        );
    }
    Ok(SyncReport {
        plan,
        applied: true,
        errors,
    })
}

pub(super) async fn set_sync_status(pool: &PgPool, in_sync: bool) {
    let mut settings = Settings::get_current_settings();
    let status = if in_sync {
        LdapSyncStatus::InSync
    } else {
        LdapSyncStatus::OutOfSync
    };
    if settings.ldap_sync_status == status {
        return;
    }
    settings.ldap_sync_status = status;
    if let Err(err) = update_current_settings(pool, settings).await {
        error!("Failed to save the directory sync status: {err}");
    }
}

/// Runs `op` in a savepoint, turning a failure into a message.
macro_rules! step {
    ($tx:expr, $errors:expr, $what:expr, |$conn:ident| $body:expr) => {{
        let mut savepoint = sqlx::Acquire::begin(&mut *$tx).await?;
        let result: Result<_, DirectoryError> = async {
            let $conn: &mut PgConnection = &mut savepoint;
            $body
        }
        .await;
        match result {
            Ok(value) => {
                savepoint.commit().await?;
                Some(value)
            }
            Err(err) => {
                savepoint.rollback().await?;
                warn!("Directory sync: {}: {err}", $what);
                $errors.push(format!("{}: {err}", $what));
                None
            }
        }
    }};
}

async fn find_user(conn: &mut PgConnection, username: &str) -> Result<User<Id>, DirectoryError> {
    User::find_by_username(&mut *conn, username)
        .await?
        .ok_or_else(|| DirectoryError::Refused(format!("user {username} not found")))
}

async fn find_group(conn: &mut PgConnection, name: &str) -> Result<Group<Id>, DirectoryError> {
    let group: Option<Group<Id>> =
        sqlx::query_as(r#"SELECT id, name, is_admin FROM "group" WHERE lower(name) = lower($1)"#)
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
    group.ok_or_else(|| DirectoryError::Refused(format!("group {name} not found")))
}

#[allow(clippy::too_many_lines)]
async fn apply_local(
    pool: &PgPool,
    config: &DirectoryConfig,
    plan: &SyncPlan,
    events: &UnboundedSender<LdapSyncEventType>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<Vec<String>, DirectoryError> {
    let mut errors = Vec::new();
    let mut emitted = Vec::new();
    let mut created = Vec::new();
    let mut touched: HashSet<String> = HashSet::new();
    let mut usermgr = UserManager::new();
    let mut tx = pool.begin().await?;

    for name in &plan.create_local_groups {
        if let Some(group) = step!(tx, errors, format!("create group {name}"), |conn| {
            Ok(Group::new(name.clone()).save(&mut *conn).await?)
        }) {
            emitted.push(LdapSyncEventType::GroupCreated { group });
        }
    }

    for username in &plan.create_local {
        let Some(remote) = plan.remote_users.get(&key(username)) else {
            continue;
        };
        if let Some(user) = step!(tx, errors, format!("add user {username}"), |conn| {
            check_username(&remote.username)
                .map_err(|err| DirectoryError::Refused(err.to_string()))?;
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
            if config.sync_account_status && remote.disabled == Some(true) {
                user.is_active = false;
            }
            Ok(user.save(&mut *conn).await?)
        }) {
            created.push(user.clone());
            emitted.push(LdapSyncEventType::UserCreated { user });
        }
    }

    for username in &plan.update_local {
        let Some(remote) = plan.remote_users.get(&key(username)) else {
            continue;
        };
        if let Some((before, after)) =
            step!(tx, errors, format!("update user {username}"), |conn| {
                let mut user = find_user(conn, username).await?;
                let before = user.clone();
                user.first_name.clone_from(&remote.first_name);
                if !remote.last_name.is_empty() {
                    user.last_name.clone_from(&remote.last_name);
                }
                user.email.clone_from(&remote.email);
                user.phone.clone_from(&remote.phone);
                user.save(&mut *conn).await?;
                Ok((before, user))
            })
        {
            emitted.push(LdapSyncEventType::UserModified { before, after });
        }
    }

    for username in &plan.record_location {
        if let Some(remote) = plan.remote_users.get(&key(username)) {
            step!(tx, errors, format!("record {username}"), |conn| {
                sqlx::query(
                    r#"UPDATE "user" SET ldap_rdn = $2, ldap_user_path = $3 WHERE lower(username) = lower($1)"#,
                )
                .bind(username)
                .bind(&remote.rdn)
                .bind(&remote.path)
                .execute(&mut *conn)
                .await?;
                Ok(())
            });
        }
    }

    for change in &plan.local_status {
        let username = &change.username;
        if let Some(user) = step!(tx, errors, format!("change status of {username}"), |conn| {
            let mut user = find_user(conn, username).await?;
            if change.active {
                user.is_active = true;
                user.save(&mut *conn).await?;
                usermgr.sync_allowed_user_devices(&user, conn).await?;
            } else {
                usermgr.disable_user(&mut user, conn).await?;
            }
            Ok(user)
        }) {
            emitted.push(if change.active {
                LdapSyncEventType::UserEnabled { user }
            } else {
                LdapSyncEventType::UserDisabled { user }
            });
        }
    }

    for (memberships, add) in [
        (&plan.add_local_members, true),
        (&plan.remove_local_members, false),
    ] {
        for membership in memberships {
            let what = format!(
                "{} {} {} group {}",
                if add { "add" } else { "remove" },
                membership.username,
                if add { "to" } else { "from" },
                membership.group
            );
            if let Some((group, user)) = step!(tx, errors, what, |conn| {
                let user = find_user(conn, &membership.username).await?;
                let group = find_group(conn, &membership.group).await?;
                if add {
                    user.add_to_group(&mut *conn, &group).await?;
                } else {
                    user.remove_from_group(&mut *conn, &group).await?;
                }
                Ok((group, user))
            }) {
                touched.insert(user.username.clone());
                emitted.push(if add {
                    LdapSyncEventType::GroupMemberAdded { group, user }
                } else {
                    LdapSyncEventType::GroupMemberRemoved { group, user }
                });
            }
        }
    }

    for username in &plan.delete_local {
        if let Some(user) = step!(tx, errors, format!("delete user {username}"), |conn| {
            let user = find_user(conn, username).await?;
            usermgr
                .delete_user_and_cleanup_devices(user.clone(), conn)
                .await?;
            Ok(user)
        }) {
            touched.remove(&user.username);
            emitted.push(LdapSyncEventType::UserDeleted { user });
        }
    }

    // Membership changes affect which locations a user may reach.
    for username in &touched {
        step!(tx, errors, format!("update access of {username}"), |conn| {
            let user = find_user(conn, username).await?;
            usermgr.sync_allowed_user_devices(&user, conn).await?;
            Ok(())
        });
    }

    tx.commit().await?;
    usermgr.send(gateway_tx);
    for event in emitted {
        let _ = events.send(event);
    }
    // Invitations go out in the background, so the sync never waits for the mail server.
    if !created.is_empty() && super::enrollment::invites_enabled(&Settings::get_current_settings())
    {
        let pool = pool.clone();
        let events = events.clone();
        tokio::spawn(async move {
            super::enrollment::send_invites(&pool, created, &events).await;
        });
    }
    Ok(errors)
}

pub(super) async fn apply_remote(
    client: &mut DirectoryClient,
    pool: &PgPool,
    plan: &SyncPlan,
    local: &[LocalUser],
    snapshot: &DirectorySnapshot,
    events: &UnboundedSender<LdapSyncEventType>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let local: HashMap<String, &LocalUser> = local.iter().map(|u| (key(&u.username), u)).collect();
    let mut remote_users = plan.remote_users.clone();
    let mut remote_groups: HashMap<String, DirectoryGroup> = snapshot
        .groups
        .iter()
        .map(|g| (key(&g.name), g.clone()))
        .collect();
    let mut failed = |what: String, err: DirectoryError| {
        warn!("Directory sync: {what}: {err}");
        errors.push(format!("{what}: {err}"));
    };

    for username in &plan.create_remote {
        let Some(user) = local.get(&key(username)) else {
            continue;
        };
        match create_remote_user(client, pool, user).await {
            Ok(created) => {
                remote_users.insert(key(username), created);
                if let Ok(Some(user)) = User::find_by_id(pool, user.id).await {
                    let _ = events.send(LdapSyncEventType::OutboundUserCreated { user });
                }
            }
            Err(err) => failed(format!("add {username} to the directory"), err),
        }
    }

    for username in &plan.update_remote {
        let (Some(user), Some(remote)) =
            (local.get(&key(username)), remote_users.get(&key(username)))
        else {
            continue;
        };
        match client
            .update_user(remote, &user.attributes(&client.config))
            .await
        {
            Ok(dn) => {
                if dn != remote.dn {
                    record_location(pool, user.id, &dn).await;
                }
                if let Ok(Some(user)) = User::find_by_id(pool, user.id).await {
                    let _ = events.send(LdapSyncEventType::OutboundUserModified { user });
                }
            }
            Err(err) => failed(format!("update {username} in the directory"), err),
        }
    }

    for change in &plan.remote_status {
        let Some(remote) = remote_users.get(&key(&change.username)) else {
            continue;
        };
        match client.set_disabled(remote, !change.active).await {
            Ok(()) => {
                if let Some(user) = local.get(&key(&change.username))
                    && let Ok(Some(user)) = User::find_by_id(pool, user.id).await
                {
                    let _ = events.send(if change.active {
                        LdapSyncEventType::OutboundUserEnabled { user }
                    } else {
                        LdapSyncEventType::OutboundUserDisabled { user }
                    });
                }
            }
            Err(err) => failed(
                format!("change status of {} in the directory", change.username),
                err,
            ),
        }
    }

    for membership in &plan.add_remote_members {
        let Some(user) = remote_users.get(&key(&membership.username)) else {
            continue;
        };
        let member = client.member_value(user);
        let result = match remote_groups.get(&key(&membership.group)) {
            Some(group) => client.add_member(&group.dn, &member).await,
            None => match client.create_group(&membership.group, &member).await {
                Ok(dn) => {
                    remote_groups.insert(
                        key(&membership.group),
                        DirectoryGroup {
                            dn,
                            name: membership.group.clone(),
                            members: vec![member.clone()],
                        },
                    );
                    Ok(())
                }
                Err(err) => Err(err),
            },
        };
        match result {
            Ok(()) => {
                let _ = events.send(LdapSyncEventType::OutboundGroupMemberAdded {
                    group: membership.group.clone(),
                    username: membership.username.clone(),
                });
            }
            Err(err) => failed(
                format!(
                    "add {} to directory group {}",
                    membership.username, membership.group
                ),
                err,
            ),
        }
    }

    for membership in &plan.remove_remote_members {
        let (Some(user), Some(group)) = (
            remote_users.get(&key(&membership.username)),
            remote_groups.get(&key(&membership.group)),
        ) else {
            continue;
        };
        let member = client.member_value(user);
        match client.remove_member(&group.dn, &member).await {
            Ok(()) => {
                let _ = events.send(LdapSyncEventType::OutboundGroupMemberRemoved {
                    group: membership.group.clone(),
                    username: membership.username.clone(),
                });
            }
            Err(err) => failed(
                format!(
                    "remove {} from directory group {}",
                    membership.username, membership.group
                ),
                err,
            ),
        }
    }

    for username in &plan.delete_remote {
        let Some(remote) = remote_users.get(&key(username)) else {
            continue;
        };
        match client.delete(&remote.dn).await {
            Ok(()) => {
                let _ = events.send(LdapSyncEventType::OutboundUserDeleted {
                    username: username.clone(),
                });
            }
            Err(err) => failed(format!("delete {username} from the directory"), err),
        }
    }
    errors
}

/// Creates `user` in the directory with a random password, which XGuard replaces with the real
/// one the next time the user signs in or changes it.
pub(super) async fn create_remote_user(
    client: &mut DirectoryClient,
    pool: &PgPool,
    user: &LocalUser,
) -> Result<DirectoryUser, DirectoryError> {
    let attributes = user.attributes(&client.config);
    let password = client.config.is_protected().then(random_password);
    let path = user.path.clone();
    let dn = client
        .add_user(&attributes, path.as_deref(), password.as_deref())
        .await?;
    sqlx::query(
        r#"UPDATE "user" SET ldap_rdn = $2, ldap_user_path = $3, ldap_pass_randomized = true WHERE id = $1"#,
    )
    .bind(user.id)
    .bind(&attributes.rdn)
    .bind(super::model::parent_dn(&dn))
    .execute(pool)
    .await?;
    let created = client
        .find_user(&attributes.username)
        .await?
        .ok_or_else(|| DirectoryError::Refused("the new directory entry was not found".into()))?;
    if client.config.sync_account_status && !user.is_active {
        client.set_disabled(&created, true).await?;
    }
    Ok(created)
}

async fn record_location(pool: &PgPool, user_id: Id, dn: &str) {
    let config = match DirectoryConfig::from_settings(&Settings::get_current_settings()) {
        Ok(config) => config,
        Err(_) => return,
    };
    let rdn = super::model::rdn_value(dn, &config.rdn_attr);
    let result =
        sqlx::query(r#"UPDATE "user" SET ldap_rdn = $2, ldap_user_path = $3 WHERE id = $1"#)
            .bind(user_id)
            .bind(rdn)
            .bind(super::model::parent_dn(dn))
            .execute(pool)
            .await;
    if let Err(err) = result {
        warn!("Failed to record the directory entry of user {user_id}: {err}");
    }
}
