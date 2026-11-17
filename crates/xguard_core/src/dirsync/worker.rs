//! The periodic sync: one background worker for the whole server.
//!
//! - It wakes every 15 seconds (or when the provider settings change) and runs a sync when the
//!   provider has directory sync on and the interval (at least a minute) has passed since the
//!   last run. The first run comes shortly after start-up or after the sync is turned on.
//! - Settings changes are queued ([`settings_changed`]); bursts are merged.
//! - A periodic run never confirms mass revocations: such a run is refused and reported in the
//!   status until an admin checks it with a dry run and confirms it with "sync now".

use std::{sync::OnceLock, time::Duration};

use sqlx::PgPool;
use tokio::{
    sync::mpsc::{UnboundedSender, unbounded_channel},
    time::{Instant, sleep_until, timeout_at},
};

use super::{SyncConfig, sync::SyncOptions};
use crate::{events::DirectorySyncEvent, grpc::GatewayCommand, sso::provider::ProviderConfig};

static QUEUE: OnceLock<UnboundedSender<()>> = OnceLock::new();

const TICK: Duration = Duration::from_secs(15);
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Tells the worker to read the provider settings again.
pub fn settings_changed() {
    if let Some(queue) = QUEUE.get() {
        let _ = queue.send(());
    }
}

/// Runs the periodic directory sync until the server stops.
pub async fn run_worker(
    pool: PgPool,
    events: UnboundedSender<DirectorySyncEvent>,
    gateway_tx: UnboundedSender<GatewayCommand>,
) {
    let (tx, mut rx) = unbounded_channel();
    if QUEUE.set(tx).is_err() {
        error!("The directory sync worker is already running");
        return;
    }
    let mut last_run: Option<(Instant, i64)> = None;
    let mut wake = Instant::now() + TICK;
    loop {
        tokio::select! {
            message = rx.recv() => {
                if message.is_none() {
                    return;
                }
                let deadline = Instant::now() + DEBOUNCE;
                while let Ok(Some(())) = timeout_at(deadline, rx.recv()).await {}
            }
            () = sleep_until(wake) => {}
        }
        wake = Instant::now() + TICK;

        let config = match ProviderConfig::current(&pool).await {
            Ok(Some(config)) if config.provider.directory_sync.directory_sync_enabled => config,
            Ok(_) => {
                last_run = None;
                continue;
            }
            Err(err) => {
                warn!("Directory sync could not read the provider settings: {err}");
                continue;
            }
        };
        let config = match SyncConfig::from_provider(&config) {
            Ok(config) => config,
            Err(err) => {
                warn!("Directory sync is misconfigured: {err}");
                continue;
            }
        };
        // A new provider starts its own schedule.
        let due = last_run.is_none_or(|(at, provider_id)| {
            provider_id != config.provider_id || at.elapsed() >= config.interval
        });
        if !due {
            continue;
        }
        match super::sync::run(&pool, &config, SyncOptions::default(), &events, &gateway_tx).await {
            Ok(report) if !report.errors.is_empty() => {
                warn!(
                    "Directory sync with {} finished with {} errors",
                    config.provider_name,
                    report.errors.len()
                );
            }
            Ok(_) => debug!("Directory sync with {} finished", config.provider_name),
            Err(err) => warn!("Directory sync with {} failed: {err}", config.provider_name),
        }
        last_run = Some((Instant::now(), config.provider_id));
    }
}
