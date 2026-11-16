//! Delivers activity log entries to the configured destinations.
//!
//! - **Isolation:** each destination has its own worker reading the event logger's broadcast,
//!   so a slow or unreachable collector never holds up the activity log or other destinations.
//! - **Batching:** entries are sent as newline-delimited JSON, at most once a second or when a
//!   batch reaches 1 MiB.
//! - **Buffering:** while a collector is down, entries wait in a buffer of up to 8 MiB per
//!   destination. When it is full, the oldest entries are dropped and counted.
//! - **Retries:** failed sends are retried with backoff, from 1 second up to 1 minute. A
//!   batch is only removed from the buffer once the collector accepts it.
//! - **TLS:** with a CA certificate configured, only that CA is trusted for the destination.
//! - **Reloads:** changes to destinations restart the workers ([`reload`]); buffered entries
//!   of a changed destination are dropped.

use std::{
    collections::{HashMap, VecDeque},
    sync::{LazyLock, Mutex},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use chrono::{NaiveDateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use tokio::{
    sync::{Notify, broadcast},
    task::JoinHandle,
    time::{Instant, sleep_until},
};
use xguard_common::db::Id;

use super::{ActivityLogStream, StoredConfig, StreamTarget};

const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_BATCH_BYTES: usize = 1024 * 1024;
const MAX_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

static RELOAD: Notify = Notify::const_new();

/// Restarts the workers with the stored destinations. Call it after changing them.
pub fn reload() {
    RELOAD.notify_one();
}

/// Delivery state of one destination, shown in the API.
#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StreamStatus {
    pub last_delivery: Option<NaiveDateTime>,
    pub last_error: Option<String>,
    pub last_error_at: Option<NaiveDateTime>,
    /// Bytes waiting to be sent.
    pub pending_bytes: usize,
    /// Entries dropped because the buffer was full or the worker fell behind.
    pub dropped: u64,
}

static STATUS: LazyLock<Mutex<HashMap<Id, StreamStatus>>> = LazyLock::new(Mutex::default);

#[must_use]
pub fn status(id: Id) -> StreamStatus {
    STATUS
        .lock()
        .ok()
        .and_then(|status| status.get(&id).cloned())
        .unwrap_or_default()
}

fn update_status(id: Id, change: impl FnOnce(&mut StreamStatus)) {
    if let Ok(mut status) = STATUS.lock() {
        change(status.entry(id).or_default());
    }
}

/// An HTTP client for one destination.
pub fn client_for(config: &StoredConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!config.url.starts_with("http://"));
    if let Some(cert) = &config.cert {
        let cert = reqwest::Certificate::from_pem(cert.as_bytes())
            .map_err(|err| format!("invalid CA certificate: {err}"))?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    builder.build().map_err(|err| err.to_string())
}

/// Sends one batch. Any 2xx status counts as delivered.
pub async fn post(
    client: &reqwest::Client,
    config: &StoredConfig,
    body: Bytes,
) -> Result<(), String> {
    let mut request = client
        .post(&config.url)
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(body);
    if let Some(username) = &config.username {
        request = request.basic_auth(username, config.password.as_deref());
    }
    let response = request.send().await.map_err(|err| {
        // Without the URL: it is already known, and errors end up in the UI.
        err.without_url().to_string()
    })?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("the collector answered {}", response.status()))
    }
}

/// Buffered lines of one destination.
#[derive(Default)]
struct Buffer {
    lines: VecDeque<Bytes>,
    bytes: usize,
    dropped: u64,
}

impl Buffer {
    /// Adds the lines of a broadcast message, dropping the oldest when over the limit.
    fn push(&mut self, message: &Bytes) {
        let mut start = 0;
        for (i, byte) in message.iter().enumerate() {
            if *byte == b'\n' {
                if i > start {
                    let line = message.slice(start..=i);
                    self.bytes += line.len();
                    self.lines.push_back(line);
                }
                start = i + 1;
            }
        }
        if start < message.len() {
            let mut line = BytesMut::from(&message[start..]);
            line.extend_from_slice(b"\n");
            self.bytes += line.len();
            self.lines.push_back(line.freeze());
        }
        while self.bytes > MAX_BUFFER_BYTES {
            let Some(line) = self.lines.pop_front() else {
                break;
            };
            self.bytes -= line.len();
            self.dropped += 1;
        }
    }

    /// The next batch, without removing it.
    fn batch(&self) -> (Bytes, usize) {
        let mut body = BytesMut::new();
        let mut count = 0;
        for line in &self.lines {
            if count > 0 && body.len() + line.len() > MAX_BATCH_BYTES {
                break;
            }
            body.extend_from_slice(line);
            count += 1;
        }
        (body.freeze(), count)
    }

    fn remove(&mut self, count: usize) {
        for line in self.lines.drain(..count) {
            self.bytes -= line.len();
        }
    }
}

async fn worker(target: StreamTarget, mut rx: broadcast::Receiver<Bytes>) {
    let id = target.id;
    let client = match client_for(&target.config) {
        Ok(client) => client,
        Err(err) => {
            error!("Activity log stream {}: {err}", target.name);
            update_status(id, |status| {
                status.last_error = Some(err);
                status.last_error_at = Some(Utc::now().naive_utc());
            });
            return;
        }
    };
    let mut buffer = Buffer::default();
    let mut backoff = MIN_BACKOFF;
    let mut next_send = Instant::now() + FLUSH_INTERVAL;
    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Ok(message) => buffer.push(&message),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!("Activity log stream {} fell behind; {missed} batches were skipped", target.name);
                    buffer.dropped += missed;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            () = sleep_until(next_send) => {
                if !buffer.lines.is_empty() {
                    let (body, count) = buffer.batch();
                    match post(&client, &target.config, body).await {
                        Ok(()) => {
                            buffer.remove(count);
                            backoff = MIN_BACKOFF;
                            update_status(id, |status| {
                                status.last_delivery = Some(Utc::now().naive_utc());
                            });
                        }
                        Err(err) => {
                            warn!("Activity log stream {}: {err}; retrying in {}s", target.name, backoff.as_secs());
                            update_status(id, |status| {
                                status.last_error = Some(err);
                                status.last_error_at = Some(Utc::now().naive_utc());
                            });
                            next_send = Instant::now() + backoff;
                            backoff = (backoff * 2).min(MAX_BACKOFF);
                            update_status(id, |status| {
                                status.pending_bytes = buffer.bytes;
                                status.dropped = buffer.dropped;
                            });
                            continue;
                        }
                    }
                }
                // Send again soon if a full batch is still waiting.
                next_send = Instant::now()
                    + if buffer.bytes >= MAX_BATCH_BYTES { Duration::ZERO } else { FLUSH_INTERVAL };
                update_status(id, |status| {
                    status.pending_bytes = buffer.bytes;
                    status.dropped = buffer.dropped;
                });
            }
        }
    }
}

/// Runs the workers, restarting them whenever [`reload`] is called.
pub async fn run(pool: PgPool, messages: broadcast::Sender<Bytes>) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    loop {
        for worker in workers.drain(..) {
            worker.abort();
        }
        match ActivityLogStream::targets(&pool).await {
            Ok(targets) => {
                if let Ok(mut status) = STATUS.lock() {
                    status.retain(|id, _| targets.iter().any(|t| t.id == *id));
                }
                for target in targets {
                    info!("Streaming the activity log to {}", target.name);
                    workers.push(tokio::spawn(worker(target, messages.subscribe())));
                }
            }
            Err(err) => error!("Failed to load activity log streams: {err}"),
        }
        RELOAD.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{Buffer, MAX_BATCH_BYTES, MAX_BUFFER_BYTES};

    #[test]
    fn splits_lines_and_batches() {
        let mut buffer = Buffer::default();
        buffer.push(&Bytes::from_static(b"{\"a\":1}\n{\"b\":2}\n"));
        buffer.push(&Bytes::from_static(b"{\"c\":3}"));
        assert_eq!(buffer.lines.len(), 3);
        let (body, count) = buffer.batch();
        assert_eq!(count, 3);
        assert_eq!(&body[..], b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n");
        buffer.remove(2);
        assert_eq!(buffer.bytes, 8);
    }

    #[test]
    fn batches_are_capped() {
        let mut buffer = Buffer::default();
        let line = Bytes::from(format!("{}\n", "x".repeat(400 * 1024 - 1)));
        for _ in 0..4 {
            buffer.push(&line);
        }
        let (body, count) = buffer.batch();
        assert_eq!(count, 2);
        assert!(body.len() <= MAX_BATCH_BYTES);
    }

    #[test]
    fn oldest_entries_are_dropped_when_full() {
        let mut buffer = Buffer::default();
        let line = Bytes::from(format!("{}\n", "y".repeat(1024 * 1024 - 1)));
        for _ in 0..10 {
            buffer.push(&line);
        }
        assert!(buffer.bytes <= MAX_BUFFER_BYTES);
        assert_eq!(buffer.dropped, 2);
        assert_eq!(buffer.lines.len(), 8);
    }
}
