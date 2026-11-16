//! Sends XGuard changes to the directory as they happen, and runs the periodic sync.
//!
//! - Handlers call [`user_changed`] or [`user_deleted`]. Those queue the change and return at
//!   once; a single worker applies queued changes in order, merging repeats of the same user
//!   that arrive close together. Nothing is queued while the integration is off.
//! - A push brings one user in line with XGuard, using the same planner as the full sync with
//!   XGuard as the authority for that user. If a push fails, the sync status turns `out of sync`
//!   and the next full sync repairs it.
//! - Passwords are pushed while the request that changes them runs ([`set_password`]), since
//!   XGuard never keeps them.

use std::{collections::BTreeSet, sync::OnceLock, time::Duration};

use sqlx::PgPool;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    time::{Instant, sleep_until},
};
use xguard_common::db::{
    Id,
    models::{Settings, User},
};

use super::{
    Authority, DirectoryClient, DirectoryConfig, DirectoryError, SyncOptions,
    model::DirectorySnapshot,
    plan::plan,
    sync::{load_local, set_sync_status},
};
use crate::{
    events::{ApiEventType, LdapSyncEventType},
    grpc::GatewayCommand,
};

#[derive(Debug)]
enum Command {
    UserChanged(Id),
    UserRenamed { id: Id, old_username: String },
    UserDeleted { username: String },
    SyncNow,
}

static QUEUE: OnceLock<UnboundedSender<Command>> = OnceLock::new();

/// Merges bursts of changes, such as a bulk edit, into one pass.
const DEBOUNCE: Duration = Duration::from_millis(250);
/// How often the worker checks whether a periodic sync is due.
const TICK: Duration = Duration::from_secs(15);

fn integration_enabled() -> bool {
    Settings::get_current_settings().ldap_enabled
}

fn send(command: Command) {
    if integration_enabled()
        && let Some(queue) = QUEUE.get()
    {
        let _ = queue.send(command);
    }
}

/// Queues a push of `user` to the directory.
pub fn user_changed(user_id: Id) {
    send(Command::UserChanged(user_id));
}

fn user_renamed(user_id: Id, old_username: &str) {
    send(Command::UserRenamed {
        id: user_id,
        old_username: old_username.to_owned(),
    });
}

/// Queues deleting `username` from the directory.
pub fn user_deleted(username: &str) {
    send(Command::UserDeleted {
        username: username.to_owned(),
    });
}

/// Queues the directory pushes an API event calls for. [`crate::appstate::AppState::emit_event`]
/// calls this for every event, so every handler that changes users or groups is covered.
pub fn on_api_event(event: &ApiEventType) {
    if !integration_enabled() {
        return;
    }
    match event {
        ApiEventType::UserAdded { user }
        | ApiEventType::UserEnabled { user }
        | ApiEventType::UserDisabled { user }
        | ApiEventType::UserGroupsModified { user, .. }
        | ApiEventType::GroupMemberAdded { user, .. }
        | ApiEventType::GroupMemberRemoved { user, .. } => user_changed(user.id),
        ApiEventType::UserModified { before, after } => {
            if before.username != after.username {
                // A rename: the entry is found by its old name, then updated.
                user_renamed(after.id, &before.username);
            } else {
                user_changed(after.id);
            }
        }
        ApiEventType::UserRemoved { user } => user_deleted(&user.username),
        ApiEventType::GroupMembersModified { added, removed, .. } => {
            for user in added.iter().chain(removed) {
                user_changed(user.id);
            }
        }
        ApiEventType::GroupsBulkAssigned { users, .. } => {
            for user in users {
                user_changed(user.id);
            }
        }
        _ => {}
    }
}

/// Starts a full sync soon.
pub fn sync_now() {
    send(Command::SyncNow);
}

/// Whether `user` is synced: enrolled or from the directory, and in a sync group if any are set.
async fn in_scope(
    pool: &PgPool,
    config: &DirectoryConfig,
    user: &User<Id>,
) -> Result<bool, DirectoryError> {
    if !user.is_enrolled_or_from_ldap() {
        return Ok(false);
    }
    if config.sync_groups.is_empty() {
        return Ok(true);
    }
    let groups = user.member_of_names(pool).await?;
    Ok(groups.iter().any(|group| config.is_sync_group(group)))
}

/// Writes a new password for `user` to the directory, if the user is synced.
///
/// Call it before storing the password in XGuard: when this fails, the change should fail too,
/// so the two never disagree.
pub async fn set_password(
    pool: &PgPool,
    user: &User<Id>,
    password: &str,
) -> Result<(), DirectoryError> {
    let config = match super::enabled_config() {
        Ok(config) => config,
        Err(DirectoryError::Disabled) => return Ok(()),
        Err(err) => return Err(err),
    };
    if !in_scope(pool, &config, user).await? {
        return Ok(());
    }
    let mut client = DirectoryClient::connect(config).await?;
    let result = async {
        match client.find_user(&user.username).await? {
            Some(remote) => client.set_password(&remote.dn, password).await,
            // The account is created by the next push, with this password unknown; it is set on
            // the user's next sign-in.
            None => Ok(()),
        }
    }
    .await;
    client.close().await;
    result?;
    sqlx::query(r#"UPDATE "user" SET ldap_pass_randomized = false WHERE id = $1"#)
        .bind(user.id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Brings one user's directory entry in line with XGuard.
pub async fn push_user(
    pool: &PgPool,
    user_id: Id,
    old_username: Option<&str>,
    events: &UnboundedSender<LdapSyncEventType>,
) -> Result<(), DirectoryError> {
    let mut config = super::enabled_config()?;
    let Some(user) = User::find_by_id(pool, user_id).await? else {
        return Ok(());
    };
    if !in_scope(pool, &config, &user).await? {
        return Ok(());
    }
    // For a single user's push, XGuard is the source of truth.
    config.authority = Authority::XGuard;
    let mut client = DirectoryClient::connect(config.clone()).await?;
    let result = async {
        let (local, local_groups) = load_local(pool).await?;
        let Some(local_user) = local.into_iter().find(|u| u.id == user_id) else {
            return Ok(());
        };
        let mut found = client.find_user(&user.username).await?;
        if found.is_none()
            && let Some(old_username) = old_username
            && let Some(entry) = client.find_user(old_username).await?
        {
            // Renamed in XGuard: rename the entry, then carry on as with any other change.
            client
                .update_user(&entry, &local_user.attributes(&config))
                .await?;
            found = client.find_user(&user.username).await?;
        }
        let mut snapshot = DirectorySnapshot {
            users: found.into_iter().collect(),
            groups: Vec::new(),
        };
        // Only the groups this user is, or should be, a member of matter.
        let mut names: BTreeSet<String> = local_user.groups.clone();
        if let Some(remote) = snapshot.users.first() {
            names.extend(
                remote
                    .member_of
                    .iter()
                    .filter_map(|dn| super::model::rdn_value(dn, &config.group_name_attr)),
            );
        }
        for name in &names {
            if let Some(group) = client.find_group(name).await? {
                snapshot.groups.push(group);
            }
        }
        let mut plan = plan(
            &config,
            std::slice::from_ref(&local_user),
            &local_groups,
            &snapshot,
        );
        // A single-user push never deletes anything.
        plan.delete_remote.clear();
        if plan.is_empty() {
            return Ok(());
        }
        let report =
            super::sync::apply_remote(&mut client, pool, &plan, &[local_user], &snapshot, events)
                .await;
        if report.is_empty() {
            Ok(())
        } else {
            Err(DirectoryError::Refused(report.join("; ")))
        }
    }
    .await;
    client.close().await;
    result
}

pub async fn delete_user(username: &str) -> Result<(), DirectoryError> {
    let config = super::enabled_config()?;
    let mut client = DirectoryClient::connect(config).await?;
    let result = async {
        if let Some(remote) = client.find_user(username).await? {
            client.delete(&remote.dn).await?;
        }
        Ok(())
    }
    .await;
    client.close().await;
    result
}

/// The directory worker: applies queued pushes and runs the periodic sync. Start it once.
pub async fn run_worker(
    pool: PgPool,
    events: UnboundedSender<LdapSyncEventType>,
    gateway_tx: UnboundedSender<GatewayCommand>,
) {
    let (tx, rx) = unbounded_channel();
    if QUEUE.set(tx).is_err() {
        error!("The directory worker is already running");
        return;
    }
    worker_loop(pool, events, gateway_tx, rx).await;
}

async fn worker_loop(
    pool: PgPool,
    events: UnboundedSender<LdapSyncEventType>,
    gateway_tx: UnboundedSender<GatewayCommand>,
    mut rx: UnboundedReceiver<Command>,
) {
    let mut next_sync = Instant::now() + TICK;
    loop {
        let command = tokio::select! {
            command = rx.recv() => match command {
                Some(command) => Some(command),
                None => return,
            },
            () = sleep_until(next_sync) => None,
        };

        let mut users = BTreeSet::new();
        let mut renamed: Vec<(Id, String)> = Vec::new();
        let mut deleted = Vec::new();
        let mut sync = false;
        let mut take = |command| match command {
            Command::UserChanged(id) => {
                users.insert(id);
            }
            Command::UserRenamed { id, old_username } => renamed.push((id, old_username)),
            Command::UserDeleted { username } => deleted.push(username),
            Command::SyncNow => sync = true,
        };
        if let Some(command) = command {
            take(command);
            let deadline = Instant::now() + DEBOUNCE;
            while let Ok(Some(command)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                take(command);
            }
        }

        let settings = Settings::get_current_settings();
        if !settings.ldap_enabled {
            next_sync = Instant::now() + TICK;
            continue;
        }
        let mut failed = false;
        for username in deleted {
            if let Err(err) = delete_user(&username).await {
                warn!("Failed to delete {username} from the directory: {err}");
                failed = true;
            }
        }
        for (id, old_username) in renamed {
            users.remove(&id);
            if let Err(err) = push_user(&pool, id, Some(&old_username), &events).await {
                warn!("Failed to push renamed user {id} to the directory: {err}");
                failed = true;
            }
        }
        for id in users {
            if let Err(err) = push_user(&pool, id, None, &events).await {
                warn!("Failed to push user {id} to the directory: {err}");
                failed = true;
            }
        }
        if failed {
            set_sync_status(&pool, false).await;
        }

        let due = Instant::now() >= next_sync;
        if sync || (due && settings.ldap_sync_enabled) {
            match DirectoryConfig::from_settings(&settings) {
                Ok(config) => {
                    let interval = config.sync_interval;
                    match super::sync::run(
                        &pool,
                        config,
                        SyncOptions::default(),
                        &events,
                        &gateway_tx,
                    )
                    .await
                    {
                        Ok(report) if !report.errors.is_empty() => {
                            warn!(
                                "Directory sync finished with {} errors",
                                report.errors.len()
                            );
                        }
                        Ok(_) => {}
                        Err(err) => warn!("Directory sync failed: {err}"),
                    }
                    next_sync = Instant::now() + interval;
                }
                Err(err) => {
                    warn!("Directory sync is misconfigured: {err}");
                    next_sync = Instant::now() + TICK;
                }
            }
        } else if due {
            next_sync = Instant::now() + TICK;
        }
    }
}
