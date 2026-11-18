//! Re-evaluates active sessions when posture policies or their assignments change.
//!
//! Handlers call [`policies_changed`] with the affected locations; it queues them and returns at
//! once. A single worker merges queued locations and, per location, evaluates every active
//! session against the device's stored snapshot (one query for sessions and snapshots, one for
//! the policies). Sessions that no longer comply, or whose device never reported posture, are
//! disconnected.

use std::{collections::BTreeSet, sync::OnceLock};

use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use xguard_common::db::{
    Id,
    models::{
        Device, User, WireguardNetwork,
        device_posture::{ActiveSessionPosture, DevicePosture, PostureSnapshot},
        vpn_client_session::VpnClientSession,
    },
};

use super::{PostureFacts, PostureResult, evaluate};
use crate::{
    events::{BidiRequestContext, BidiStreamEvent, BidiStreamEventType, DesktopClientMfaEvent},
    grpc::GatewayCommand,
    mfa_engine::authorize::{EventChannels, SessionDisconnectReason, disconnect_session},
};

static QUEUE: OnceLock<UnboundedSender<Id>> = OnceLock::new();

/// Queues re-evaluation of the given locations. Does nothing before the worker runs.
pub fn policies_changed<I: IntoIterator<Item = Id>>(locations: I) {
    if let Some(queue) = QUEUE.get() {
        for location in locations {
            if queue.send(location).is_err() {
                warn!("Posture re-evaluation worker is not running");
                return;
            }
        }
    }
}

/// Runs the re-evaluation worker until the process ends.
pub async fn run_worker(
    pool: PgPool,
    gateway_tx: UnboundedSender<GatewayCommand>,
    bidi_event_tx: UnboundedSender<BidiStreamEvent>,
) {
    let (tx, rx) = unbounded_channel();
    if QUEUE.set(tx).is_err() {
        error!("Posture re-evaluation worker started twice");
        return;
    }
    run(pool, EventChannels::new(gateway_tx, bidi_event_tx), rx).await;
}

async fn run(pool: PgPool, channels: EventChannels, mut rx: UnboundedReceiver<Id>) {
    info!("Posture re-evaluation worker started");
    while let Some(first) = rx.recv().await {
        let mut locations = BTreeSet::from([first]);
        while let Ok(location) = rx.try_recv() {
            locations.insert(location);
        }
        for location_id in locations {
            match reevaluate_location(&pool, &channels, location_id).await {
                Ok(0) => {}
                Ok(count) => info!(
                    "Disconnected {count} device(s) from location {location_id} after a posture \
                     policy change"
                ),
                Err(err) => {
                    error!("Failed to re-evaluate posture for location {location_id}: {err}")
                }
            }
        }
    }
}

/// Re-evaluates one location and returns how many devices were disconnected.
pub async fn reevaluate_location(
    pool: &PgPool,
    channels: &EventChannels,
    location_id: Id,
) -> sqlx::Result<usize> {
    let mut conn = pool.acquire().await?;
    let Some(location) = WireguardNetwork::find_by_id(&mut *conn, location_id).await? else {
        return Ok(0);
    };
    let policies = DevicePosture::find_for_location(&mut conn, location_id).await?;
    if policies.is_empty() {
        return Ok(0);
    }
    let sessions = ActiveSessionPosture::for_location(&mut *conn, location_id).await?;
    let today = Utc::now().date_naive();

    let mut failing: Vec<(Id, Option<PostureFacts>, Vec<String>)> = Vec::new();
    for session in sessions {
        if failing
            .iter()
            .any(|(device, _, _)| *device == session.device_id)
        {
            continue;
        }
        let facts = session.facts.as_ref().and_then(PostureFacts::from_json);
        if let PostureResult::Fail(failures) = evaluate(&policies, facts.as_ref(), today) {
            failing.push((session.device_id, facts, failures));
        }
    }
    drop(conn);

    let mut disconnected = 0;
    for (device_id, facts, failures) in failing {
        let mut transaction = pool.begin().await?;
        let Some(device) = Device::find_by_id(&mut *transaction, device_id).await? else {
            continue;
        };
        let Some(user) = User::find_by_id(&mut *transaction, device.user_id).await? else {
            continue;
        };
        if facts.is_some() {
            PostureSnapshot::set_result(&mut *transaction, device_id, false, &failures).await?;
        }
        let active = VpnClientSession::get_all_active_device_sessions_in_location(
            &mut *transaction,
            location_id,
            device_id,
        )
        .await?;
        for session in active {
            if let Err(err) = disconnect_session(
                channels,
                &mut transaction,
                session,
                &location,
                &user,
                &device,
                SessionDisconnectReason::Disconnected,
            )
            .await
            {
                error!("Failed to disconnect device {device} after a posture change: {err}");
            }
        }
        transaction.commit().await?;
        // Also drops the peer of a device that had no session yet.
        if let Err(err) = channels
            .gateway_tx
            .send(GatewayCommand::VpnSessionDeauthorized(
                location_id,
                device.clone(),
            ))
        {
            error!("Failed to send gateway deauthorization: {err}");
        }
        warn!(
            "Device {device} of {} no longer meets the posture policies of location {location}: \
             {}",
            user.username,
            failures.join("; ")
        );
        let context = BidiRequestContext {
            timestamp: Utc::now().naive_utc(),
            user_id: user.id,
            username: user.username.clone(),
            ip: None,
            device_name: format!("{device}"),
        };
        if let Err(err) = channels.emit_event(BidiStreamEvent {
            context,
            event: BidiStreamEventType::DesktopClientMfa(Box::new(
                DesktopClientMfaEvent::PostureCheckFailed {
                    device,
                    location: location.clone(),
                    facts,
                    failed_checks: failures,
                },
            )),
        }) {
            error!("Failed to emit posture event: {err}");
        }
        disconnected += 1;
    }
    Ok(disconnected)
}
