//! Desktop client configuration sync (`InstanceInfo` over Edge's `POST /api/v1/poll`).
//!
//! A client presents its device's polling token and the revision of the configuration it applied
//! last. Core builds the device's current configuration, derives a revision from its encoded
//! bytes and answers either with the full configuration or with `not_modified`, so an unchanged
//! configuration costs the client one small request and no local writes.
//!
//! Abuse limits (per Edge connection, in memory, bounded):
//! - a device may poll at most once per [`MIN_DEVICE_POLL_INTERVAL`];
//! - a client address may present at most [`MAX_FAILURES_PER_WINDOW`] unknown tokens per
//!   [`FAILURE_WINDOW`].
//!
//! Tokens are looked up by their SHA-256 digest (see [`PollingToken`]), so neither the lookup nor
//! the comparison leaks anything useful through timing.

use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use prost::Message;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::Status;
use xguard_common::db::{
    Id,
    models::{
        Device, User,
        polling_token::{MAX_PRESENTED_TOKEN_LENGTH, PollingToken},
    },
};
use xguard_core::grpc::utils::{build_device_config_response, parse_client_ip_agent};
use xguard_proto::{
    client_types::{DeviceConfigResponse, InstanceInfoRequest, InstanceInfoResponse},
    proxy::DeviceInfo,
};

/// Interval clients are asked to wait between polls.
pub(crate) const SUGGESTED_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// A device polling more often than this is refused with `RESOURCE_EXHAUSTED`.
#[cfg(not(test))]
pub(crate) const MIN_DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Shorter in tests, so a test can poll repeatedly without waiting long.
#[cfg(test)]
pub(crate) const MIN_DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Window for counting unknown tokens per client address.
pub(crate) const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Unknown tokens a client address may present per [`FAILURE_WINDOW`].
pub(crate) const MAX_FAILURES_PER_WINDOW: u32 = 10;
/// Upper bound on tracked keys per limiter, so memory stays bounded under a flood.
const MAX_TRACKED_KEYS: usize = 50_000;
/// Longest revision string a client may send back.
const MAX_REVISION_LENGTH: usize = 128;
/// Prefix of revisions produced by this version of the scheme.
const REVISION_PREFIX: &str = "x1-";

/// Fixed-window counter keyed by `K`, bounded to [`MAX_TRACKED_KEYS`] entries.
pub(crate) struct WindowLimiter<K> {
    window: Duration,
    limit: u32,
    entries: HashMap<K, (Instant, u32)>,
}

impl<K: Eq + Hash + Clone> WindowLimiter<K> {
    pub(crate) fn new(window: Duration, limit: u32) -> Self {
        Self {
            window,
            limit,
            entries: HashMap::new(),
        }
    }

    /// Counts one event for `key` at `now`; returns whether it is within the limit.
    pub(crate) fn hit(&mut self, key: &K, now: Instant) -> bool {
        if !self.entries.contains_key(key) && self.entries.len() >= MAX_TRACKED_KEYS {
            let window = self.window;
            self.entries
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < window);
            if self.entries.len() >= MAX_TRACKED_KEYS {
                // Still full of live entries: refuse rather than grow without bound.
                return false;
            }
        }
        let entry = self.entries.entry(key.clone()).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limit
    }

    /// Whether `key` is currently over the limit, without counting an event.
    pub(crate) fn is_blocked(&self, key: &K, now: Instant) -> bool {
        self.entries.get(key).is_some_and(|(start, count)| {
            now.saturating_duration_since(*start) < self.window && *count >= self.limit
        })
    }
}

struct Limits {
    per_device: WindowLimiter<Id>,
    failures: WindowLimiter<IpAddr>,
}

pub(crate) struct PollingServer {
    pool: PgPool,
    limits: Mutex<Limits>,
}

/// Revision of a configuration: a digest of its protobuf encoding. Encoding is deterministic for
/// these messages (no maps), so equal configurations have equal revisions.
pub(crate) fn config_revision(config: &DeviceConfigResponse) -> String {
    let digest = Sha256::digest(config.encode_to_vec());
    let mut revision = String::with_capacity(REVISION_PREFIX.len() + 32);
    revision.push_str(REVISION_PREFIX);
    for byte in &digest[..16] {
        revision.push_str(&format!("{byte:02x}"));
    }
    revision
}

impl PollingServer {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self {
            pool,
            limits: Mutex::new(Limits {
                per_device: WindowLimiter::new(MIN_DEVICE_POLL_INTERVAL, 1),
                failures: WindowLimiter::new(FAILURE_WINDOW, MAX_FAILURES_PER_WINDOW),
            }),
        }
    }

    fn limits(&self) -> std::sync::MutexGuard<'_, Limits> {
        self.limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[instrument(skip_all)]
    pub(crate) async fn info(
        &self,
        request: InstanceInfoRequest,
        device_info: Option<DeviceInfo>,
    ) -> Result<InstanceInfoResponse, Status> {
        let client_ip = parse_client_ip_agent(&device_info).ok().map(|(ip, _)| ip);
        let now = Instant::now();
        if let Some(ip) = client_ip
            && self.limits().failures.is_blocked(&ip, now)
        {
            warn!("Config polling: too many unknown tokens from {ip}, refusing");
            return Err(Status::resource_exhausted("too many requests"));
        }

        let token = if request.token.is_empty() || request.token.len() > MAX_PRESENTED_TOKEN_LENGTH
        {
            None
        } else {
            PollingToken::find(&self.pool, &request.token)
                .await
                .map_err(|err| {
                    error!("Config polling: failed to look up the polling token: {err}");
                    Status::internal("unexpected error")
                })?
        };
        let Some(token) = token else {
            if let Some(ip) = client_ip {
                self.limits().failures.hit(&ip, now);
            }
            warn!("Config polling with an unknown token from {client_ip:?}");
            return Err(Status::unauthenticated("unauthorized"));
        };

        if !self.limits().per_device.hit(&token.device_id, now) {
            debug!(
                "Config polling: device {} polls too often, refusing",
                token.device_id
            );
            return Err(Status::resource_exhausted("polling too often"));
        }

        let device = Device::find_by_id(&self.pool, token.device_id)
            .await
            .map_err(|err| {
                error!("Config polling: failed to load device: {err}");
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| Status::unauthenticated("unauthorized"))?;
        let user = User::find_by_id(&self.pool, device.user_id)
            .await
            .map_err(|err| {
                error!("Config polling: failed to load user: {err}");
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| Status::unauthenticated("unauthorized"))?;
        if !user.is_active {
            info!(
                "Config polling refused for device {} of disabled user {}",
                device.name, user.username
            );
            return Err(Status::permission_denied("user is disabled"));
        }

        let config = build_device_config_response(&self.pool, device, None, device_info).await?;
        let revision = config_revision(&config);
        let known = request
            .config_revision
            .as_deref()
            .filter(|known| known.len() <= MAX_REVISION_LENGTH);
        let poll_interval_secs =
            Some(u32::try_from(SUGGESTED_POLL_INTERVAL.as_secs()).unwrap_or(u32::MAX));
        if known == Some(revision.as_str()) {
            debug!(
                "Config polling: configuration of device {} unchanged",
                token.device_id
            );
            return Ok(InstanceInfoResponse {
                device_config: None,
                config_revision: Some(revision),
                not_modified: Some(true),
                poll_interval_secs,
            });
        }
        Ok(InstanceInfoResponse {
            device_config: Some(config),
            config_revision: Some(revision),
            not_modified: Some(false),
            poll_interval_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limiter_counts_per_key_and_resets() {
        let start = Instant::now();
        let mut limiter = WindowLimiter::new(Duration::from_secs(10), 2);
        assert!(limiter.hit(&1, start));
        assert!(limiter.hit(&1, start));
        assert!(!limiter.hit(&1, start));
        assert!(limiter.is_blocked(&1, start));
        assert!(limiter.hit(&2, start));
        let later = start + Duration::from_secs(10);
        assert!(!limiter.is_blocked(&1, later));
        assert!(limiter.hit(&1, later));
    }

    #[test]
    fn revision_follows_content() {
        let mut config = DeviceConfigResponse::default();
        let first = config_revision(&config);
        assert!(first.starts_with(REVISION_PREFIX));
        assert_eq!(first.len(), REVISION_PREFIX.len() + 32);
        assert_eq!(first, config_revision(&config));
        config.token = Some("x".into());
        assert_ne!(first, config_revision(&config));
    }
}
