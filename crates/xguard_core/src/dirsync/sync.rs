//! Runs a sync: reads both sides, plans, and applies the plan.
//!
//! - **Reading:** one snapshot of the directory (see [`super::DirectoryApi::snapshot`]) and
//!   three queries on the XGuard side.
//! - **Applying:** one transaction, with each account change in its own savepoint, so one bad
//!   entry (a duplicate email, say) is reported without blocking the rest. Before an admin is
//!   disabled, deleted or loses an admin group, the transaction checks again that another
//!   active admin remains. Gateways are updated once per touched user, after commit.
//! - **Events:** every change is sent to the activity log as a directory sync event, and to the
//!   LDAP push queue (which ignores it unless LDAP sync is on).
//! - **One at a time:** the periodic run and an admin's "sync now" never overlap.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Mutex,
};

use chrono::{NaiveDateTime, Utc};
use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use tokio::sync::mpsc::UnboundedSender;
use xguard_common::db::{
    Id,
    models::{User, group::Group},
};

use super::{
    DirSyncError, DirectoryApi, SyncConfig,
    plan::{LocalGroup, LocalUser, SyncPlan, plan},
};
use crate::{
    events::{DirectorySyncEvent, DirectorySyncEventType},
    grpc::GatewayCommand,
    user_management::UserManager,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct SyncOptions {
    /// Compute the plan without changing anything.
    pub dry_run: bool,
    /// Allow a run that disables or deletes many accounts (see
    /// [`SyncPlan::check_revocations`]).
    pub confirm_revocations: bool,
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub plan: SyncPlan,
    pub applied: bool,
    pub errors: Vec<String>,
}

/// How the last periodic or manual (not dry) run went.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LastRun {
    pub finished: NaiveDateTime,
    pub success: bool,
    /// Why the run failed, or how many changes failed.
    pub message: Option<String>,
    pub changes: usize,
}

static LAST_RUN: Mutex<Option<LastRun>> = Mutex::new(None);
static RUN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[must_use]
pub fn last_run() -> Option<LastRun> {
    LAST_RUN.lock().ok().and_then(|last| last.clone())
}

fn changes(plan: &SyncPlan) -> usize {
    plan.create_users.len()
        + plan.update_users.len()
        + plan.enable_users.len()
        + plan.disable_users.len()
        + plan.delete_users.len()
        + plan.create_groups.len()
        + plan.add_members.len()
        + plan.remove_members.len()
}

fn record(result: &Result<SyncReport, DirSyncError>) {
    let entry = match result {
        Ok(report) => LastRun {
            finished: Utc::now().naive_utc(),
            success: report.errors.is_empty(),
            message: (!report.errors.is_empty())
                .then(|| format!("{} changes failed", report.errors.len())),
            changes: changes(&report.plan),
        },
        Err(err) => LastRun {
            finished: Utc::now().naive_utc(),
            success: false,
            message: Some(err.to_string()),
            changes: 0,
        },
    };
    if let Ok(mut last) = LAST_RUN.lock() {
        *last = Some(entry);
    }
}

/// XGuard accounts with their groups and the directory identity for `provider_id` (none when
/// the identities do not apply, such as for unsaved settings of another directory).
pub async fn load_local(
    pool: &PgPool,
    provider_id: Option<Id>,
) -> Result<(Vec<LocalUser>, Vec<LocalGroup>), sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Id,
        username: String,
        email: String,
        first_name: String,
        last_name: String,
        is_active: bool,
        openid_sub: Option<String>,
        external_id: Option<String>,
        sync_disabled: Option<bool>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.is_active,
        u.openid_sub, i.external_id, i.sync_disabled FROM "user" u
        LEFT JOIN user_directory_identity i ON i.user_id = u.id AND i.provider_id = $1"#,
    )
    .bind(provider_id.unwrap_or(-1))
    .fetch_all(pool)
    .await?;
    let memberships: Vec<(Id, String, bool)> = sqlx::query_as(
        r#"SELECT gu.user_id, g.name, g.is_admin FROM group_user gu JOIN "group" g ON g.id = gu.group_id"#,
    )
    .fetch_all(pool)
    .await?;
    let groups: Vec<(String, bool)> = sqlx::query_as(r#"SELECT name, is_admin FROM "group""#)
        .fetch_all(pool)
        .await?;
    let mut by_user: HashMap<Id, (BTreeSet<String>, bool)> = HashMap::new();
    for (user_id, group, is_admin) in memberships {
        let entry = by_user.entry(user_id).or_default();
        entry.0.insert(group);
        entry.1 |= is_admin;
    }
    let users = rows
        .into_iter()
        .map(|row| {
            let (groups, is_admin) = by_user.remove(&row.id).unwrap_or_default();
            LocalUser {
                id: row.id,
                username: row.username,
                email: row.email,
                first_name: row.first_name,
                last_name: row.last_name,
                is_active: row.is_active,
                is_admin,
                openid_sub: row.openid_sub,
                external_id: row.external_id,
                sync_disabled: row.sync_disabled.unwrap_or(false),
                groups,
            }
        })
        .collect();
    let groups = groups
        .into_iter()
        .map(|(name, is_admin)| LocalGroup { name, is_admin })
        .collect();
    Ok((users, groups))
}

/// Reads the directory and XGuard, plans and (unless it is a dry run) applies the changes.
/// A `provider_id` of 0 (unsaved settings) ignores the stored directory identities.
pub async fn run(
    pool: &PgPool,
    config: &SyncConfig,
    options: SyncOptions,
    events: &UnboundedSender<DirectorySyncEvent>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<SyncReport, DirSyncError> {
    let _guard = RUN_LOCK.lock().await;
    let result = run_locked(pool, config, options, events, gateway_tx).await;
    if !options.dry_run {
        record(&result);
    }
    result
}

async fn run_locked(
    pool: &PgPool,
    config: &SyncConfig,
    options: SyncOptions,
    events: &UnboundedSender<DirectorySyncEvent>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<SyncReport, DirSyncError> {
    let api = DirectoryApi::connect(config).await?;
    let snapshot = api.snapshot(config).await?;
    let provider_id = (config.provider_id != 0).then_some(config.provider_id);
    let (users, groups) = load_local(pool, provider_id).await?;
    let plan = plan(config, &users, &groups, &snapshot);
    if options.dry_run {
        return Ok(SyncReport {
            plan,
            applied: false,
            errors: Vec::new(),
        });
    }
    plan.check_revocations(options.confirm_revocations)
        .map_err(DirSyncError::Refused)?;
    let errors = apply(pool, config, &plan, events, gateway_tx).await?;
    if !plan.is_empty() {
        info!(
            "Directory sync with {}: {} accounts created, {} updated, {} enabled, {} disabled, \
             {} deleted, {} memberships added, {} removed; {} errors",
            config.provider_name,
            plan.create_users.len(),
            plan.update_users.len(),
            plan.enable_users.len(),
            plan.disable_users.len(),
            plan.delete_users.len(),
            plan.add_members.len(),
            plan.remove_members.len(),
            errors.len()
        );
    }
    Ok(SyncReport {
        plan,
        applied: true,
        errors,
    })
}

/// Runs `body` in a savepoint, turning a failure into a message.
macro_rules! step {
    ($tx:expr, $errors:expr, $what:expr, |$conn:ident| $body:expr) => {{
        let mut savepoint = sqlx::Acquire::begin(&mut *$tx).await?;
        let result: Result<_, DirSyncError> = async {
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

async fn find_user(conn: &mut PgConnection, id: Id) -> Result<User<Id>, DirSyncError> {
    User::find_by_id(&mut *conn, id)
        .await?
        .ok_or_else(|| DirSyncError::Refused(format!("user {id} no longer exists")))
}

async fn find_member(
    conn: &mut PgConnection,
    id: Option<Id>,
    username: &str,
) -> Result<User<Id>, DirSyncError> {
    match id {
        Some(id) => find_user(conn, id).await,
        None => User::find_by_username(&mut *conn, username)
            .await?
            .ok_or_else(|| DirSyncError::Refused(format!("user {username} was not created"))),
    }
}

async fn find_group(conn: &mut PgConnection, name: &str) -> Result<Group<Id>, DirSyncError> {
    let group: Option<Group<Id>> =
        sqlx::query_as(r#"SELECT id, name, is_admin FROM "group" WHERE lower(name) = lower($1)"#)
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
    group.ok_or_else(|| DirSyncError::Refused(format!("group {name} not found")))
}

/// Refuses to take away the last active admin (checked again inside the transaction).
async fn keep_an_admin(conn: &mut PgConnection, user_id: Id) -> Result<(), DirSyncError> {
    let others: i64 = sqlx::query_scalar(
        r#"SELECT count(DISTINCT u.id) FROM "user" u JOIN group_user gu ON gu.user_id = u.id
        JOIN "group" g ON g.id = gu.group_id WHERE g.is_admin AND u.is_active AND u.id <> $1"#,
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    if others == 0 {
        return Err(DirSyncError::Refused(
            "this is the last active admin".into(),
        ));
    }
    Ok(())
}

/// Refuses to remove `(user_id, group_id)` if doing so would leave no active admin anywhere.
async fn keep_an_admin_without_membership(
    conn: &mut PgConnection,
    user_id: Id,
    group_id: Id,
) -> Result<(), DirSyncError> {
    let has_other: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM group_user gu
            JOIN "group" g ON g.id = gu.group_id
            JOIN "user" u ON u.id = gu.user_id
            WHERE g.is_admin AND u.is_active AND NOT (u.id = $1 AND g.id = $2)
        )"#,
    )
    .bind(user_id)
    .bind(group_id)
    .fetch_one(&mut *conn)
    .await?;
    if !has_other {
        return Err(DirSyncError::Refused(
            "this is the last active admin".into(),
        ));
    }
    Ok(())
}

async fn is_active_admin(conn: &mut PgConnection, user: &User<Id>) -> Result<bool, DirSyncError> {
    Ok(user.is_active && user.is_admin(&mut *conn).await?)
}

async fn set_sync_disabled(
    conn: &mut PgConnection,
    provider_id: Id,
    user: &User<Id>,
    disabled: bool,
) -> Result<(), sqlx::Error> {
    let res = sqlx::query(
        "UPDATE user_directory_identity SET sync_disabled = $3 WHERE provider_id = $1 AND user_id = $2",
    )
    .bind(provider_id)
    .bind(user.id)
    .bind(disabled)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 0
        && disabled
        && let Some(external_id) = user.openid_sub.as_deref()
    {
        sqlx::query(
            "INSERT INTO user_directory_identity (user_id, provider_id, external_id, sync_disabled) \
             VALUES ($1, $2, $3, true) \
             ON CONFLICT (user_id, provider_id) DO UPDATE SET sync_disabled = true",
        )
        .bind(user.id)
        .bind(provider_id)
        .bind(external_id)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn link(
    conn: &mut PgConnection,
    provider_id: Id,
    user_id: Id,
    external_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_directory_identity (user_id, provider_id, external_id) \
         VALUES ($1, $2, $3) ON CONFLICT (user_id, provider_id) \
         DO UPDATE SET external_id = EXCLUDED.external_id",
    )
    .bind(user_id)
    .bind(provider_id)
    .bind(external_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn apply(
    pool: &PgPool,
    config: &SyncConfig,
    plan: &SyncPlan,
    events: &UnboundedSender<DirectorySyncEvent>,
    gateway_tx: &UnboundedSender<GatewayCommand>,
) -> Result<Vec<String>, DirSyncError> {
    let provider_id = config.provider_id;
    let mut errors = Vec::new();
    let mut emitted = Vec::new();
    // Accounts whose access to locations may have changed, and accounts LDAP should hear of.
    let mut touched: HashSet<Id> = HashSet::new();
    let mut changed: HashSet<Id> = HashSet::new();
    let mut deleted: Vec<String> = Vec::new();
    let mut usermgr = UserManager::new();
    let mut tx = pool.begin().await?;

    for link_user in &plan.link_users {
        let what = format!("link {} to the directory", link_user.username);
        step!(tx, errors, what, |conn| {
            link(conn, provider_id, link_user.user_id, &link_user.external_id).await?;
            Ok(())
        });
    }

    for name in &plan.create_groups {
        if let Some(group) = step!(tx, errors, format!("create group {name}"), |conn| {
            Ok(Group::new(name.clone()).save(&mut *conn).await?)
        }) {
            emitted.push(DirectorySyncEventType::GroupCreated { group });
        }
    }

    for new in &plan.create_users {
        if let Some(user) = step!(tx, errors, format!("add user {}", new.username), |conn| {
            let user = User::new(
                new.username.clone(),
                None,
                new.last_name.clone(),
                new.first_name.clone(),
                new.email.clone(),
                new.phone.clone(),
            )
            .save(&mut *conn)
            .await?;
            link(conn, provider_id, user.id, &new.external_id).await?;
            Ok(user)
        }) {
            changed.insert(user.id);
            emitted.push(DirectorySyncEventType::UserCreated { user });
        }
    }

    for change in &plan.update_users {
        let what = format!("update user {}", change.username);
        if let Some((before, after)) = step!(tx, errors, what, |conn| {
            let mut user = find_user(conn, change.user_id).await?;
            let before = user.clone();
            user.first_name.clone_from(&change.first_name);
            user.last_name.clone_from(&change.last_name);
            user.email.clone_from(&change.email);
            user.save(&mut *conn).await?;
            Ok((before, user))
        }) {
            changed.insert(after.id);
            emitted.push(DirectorySyncEventType::UserModified { before, after });
        }
    }

    for change in &plan.enable_users {
        let what = format!("enable user {}", change.username);
        if let Some(user) = step!(tx, errors, what, |conn| {
            let mut user = find_user(conn, change.user_id).await?;
            user.is_active = true;
            user.save(&mut *conn).await?;
            set_sync_disabled(conn, provider_id, &user, false).await?;
            Ok(user)
        }) {
            touched.insert(user.id);
            changed.insert(user.id);
            emitted.push(DirectorySyncEventType::UserEnabled { user });
        }
    }

    for change in &plan.disable_users {
        let what = format!("disable user {} ({})", change.username, change.reason);
        if let Some((user, mut step_mgr)) = step!(tx, errors, what, |conn| {
            let mut user = find_user(conn, change.user_id).await?;
            if is_active_admin(conn, &user).await? {
                keep_an_admin(conn, user.id).await?;
            }
            let mut step_mgr = UserManager::new();
            step_mgr.disable_user(&mut user, conn).await?;
            set_sync_disabled(conn, provider_id, &user, true).await?;
            Ok((user, step_mgr))
        }) {
            usermgr.append(&mut step_mgr);
            touched.remove(&user.id);
            changed.insert(user.id);
            emitted.push(DirectorySyncEventType::UserDisabled { user });
        }
    }

    for (memberships, add) in [(&plan.add_members, true), (&plan.remove_members, false)] {
        for membership in memberships {
            let what = format!(
                "{} {} {} group {}",
                if add { "add" } else { "remove" },
                membership.username,
                if add { "to" } else { "from" },
                membership.group
            );
            if let Some((group, user)) = step!(tx, errors, what, |conn| {
                let user = find_member(conn, membership.user_id, &membership.username).await?;
                let group = find_group(conn, &membership.group).await?;
                if add {
                    user.add_to_group(&mut *conn, &group).await?;
                } else {
                    if group.is_admin && is_active_admin(conn, &user).await? {
                        keep_an_admin_without_membership(conn, user.id, group.id).await?;
                    }
                    user.remove_from_group(&mut *conn, &group).await?;
                }
                Ok((group, user))
            }) {
                touched.insert(user.id);
                changed.insert(user.id);
                emitted.push(if add {
                    DirectorySyncEventType::GroupMemberAdded { group, user }
                } else {
                    DirectorySyncEventType::GroupMemberRemoved { group, user }
                });
            }
        }
    }

    for change in &plan.delete_users {
        let what = format!("delete user {} ({})", change.username, change.reason);
        if let Some((user, mut step_mgr)) = step!(tx, errors, what, |conn| {
            let user = find_user(conn, change.user_id).await?;
            if is_active_admin(conn, &user).await? {
                keep_an_admin(conn, user.id).await?;
            }
            let mut step_mgr = UserManager::new();
            step_mgr
                .delete_user_and_cleanup_devices(user.clone(), conn)
                .await?;
            Ok((user, step_mgr))
        }) {
            usermgr.append(&mut step_mgr);
            touched.remove(&user.id);
            changed.remove(&user.id);
            deleted.push(user.username.clone());
            emitted.push(DirectorySyncEventType::UserDeleted { user });
        }
    }

    // Membership and status changes affect which locations a user may reach. Disabling and
    // deleting update gateways themselves.
    for user_id in &touched {
        if let Some(mut step_mgr) = step!(
            tx,
            errors,
            format!("update access of user {user_id}"),
            |conn| {
                let user = find_user(conn, *user_id).await?;
                let mut step_mgr = UserManager::new();
                step_mgr.sync_allowed_user_devices(&user, conn).await?;
                Ok(step_mgr)
            }
        ) {
            usermgr.append(&mut step_mgr);
        }
    }

    tx.commit().await?;
    usermgr.send(gateway_tx);
    for event in emitted {
        let _ = events.send(DirectorySyncEvent {
            provider: config.provider_name.clone(),
            event,
        });
    }
    for user_id in changed {
        crate::directory::push::user_changed(user_id);
    }
    for username in deleted {
        crate::directory::push::user_deleted(&username);
    }
    Ok(errors)
}
