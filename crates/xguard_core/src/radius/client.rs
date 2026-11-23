//! Async UDP RADIUS client for MFA verification.
//!
//! Uses fresh CSPRNG Request Authenticators per request, enforces RFC 3579
//! `Message-Authenticator` on every request and response (BlastRADIUS protection),
//! and fails over from primary to secondary server on timeout or transport error.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::{UdpSocket, lookup_host};
use tracing::{debug, warn};

use super::packet::{
    AccessRequest, Decision, MAX_PACKET_LEN, PacketError, build_access_request, verify_response,
};

/// Maximum sanitized Reply-Message length surfaced to clients.
const MAX_REPLY_MESSAGE_CHARS: usize = 512;

/// One RADIUS server endpoint and its shared secret.
#[derive(Clone)]
pub struct RadiusServerConfig {
    pub host: String,
    pub port: u16,
    pub secret: SecretString,
}

impl std::fmt::Debug for RadiusServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadiusServerConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Complete client configuration for RADIUS MFA.
#[derive(Clone, Debug)]
pub struct RadiusClientConfig {
    pub primary: RadiusServerConfig,
    pub secondary: Option<RadiusServerConfig>,
    pub timeout: Duration,
    pub retries: u8,
    pub nas_identifier: String,
    pub nas_ip_address: Option<IpAddr>,
}

impl RadiusClientConfig {
    /// Builds a client config from persisted [`xguard_common::db::models::radius::RadiusSettings`].
    /// Returns `None` if primary host or secret is missing.
    #[must_use]
    pub fn from_settings(
        settings: &xguard_common::db::models::radius::RadiusSettings,
    ) -> Option<Self> {
        let primary_host = settings.primary_host.trim();
        let primary_secret = settings.primary_secret.expose_secret();
        if primary_host.is_empty() || primary_secret.is_empty() {
            return None;
        }
        let secondary = settings
            .secondary_host
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(|host| RadiusServerConfig {
                host: host.to_owned(),
                port: settings.secondary_port,
                secret: SecretString::from(
                    settings
                        .secondary_secret
                        .as_ref()
                        .map(|s| s.expose_secret().to_owned())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| primary_secret.to_owned()),
                ),
            });
        Some(Self {
            primary: RadiusServerConfig {
                host: primary_host.to_owned(),
                port: settings.primary_port,
                secret: SecretString::from(primary_secret.to_owned()),
            },
            secondary,
            timeout: Duration::from_secs(settings.timeout_secs.clamp(1, 30)),
            retries: settings.retries.clamp(1, 10),
            nas_identifier: if settings.nas_identifier.trim().is_empty() {
                "xguard".to_owned()
            } else {
                settings.nas_identifier.trim().to_owned()
            },
            nas_ip_address: settings.nas_ip_address,
        })
    }
}

/// Verified outcome of an Access-Request exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadiusOutcome {
    Accept {
        reply_message: Option<String>,
    },
    Reject {
        reply_message: Option<String>,
    },
    Challenge {
        reply_message: Option<String>,
        state: Vec<u8>,
    },
}

/// Transport or protocol errors from a RADIUS exchange.
#[derive(Debug, thiserror::Error)]
pub enum RadiusError {
    #[error("RADIUS server host could not be resolved: {0}")]
    Resolve(String),
    #[error("RADIUS server did not respond in time")]
    Timeout,
    #[error("RADIUS packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("RADIUS network error: {0}")]
    Io(#[from] std::io::Error),
}

/// Removes ASCII control characters (except newlines) and bounds length so a
/// RADIUS server's Reply-Message is safe to display in web, desktop, and mobile UIs.
#[must_use]
pub fn sanitize_reply_message(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let cleaned: String = text
        .chars()
        .filter(|&c| c == '\n' || !c.is_control())
        .take(MAX_REPLY_MESSAGE_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Sends a RADIUS Access-Request (optionally continuing an Access-Challenge via `state`),
/// trying `primary` first and failing over to `secondary` on timeout or network failure.
pub async fn authenticate(
    config: &RadiusClientConfig,
    user_name: &str,
    password: &str,
    state: Option<&[u8]>,
) -> Result<RadiusOutcome, RadiusError> {
    let req = AccessRequest {
        user_name,
        password: password.as_bytes(),
        nas_identifier: &config.nas_identifier,
        nas_ip_address: config.nas_ip_address,
        state,
    };

    match send_to_server(&config.primary, &req, config.timeout, config.retries).await {
        Ok(outcome) => Ok(outcome),
        Err(primary_err) => {
            if let Some(secondary) = &config.secondary {
                warn!(
                    "Primary RADIUS server {}:{} failed ({primary_err}); failing over to secondary {}:{}",
                    config.primary.host, config.primary.port, secondary.host, secondary.port
                );
                send_to_server(secondary, &req, config.timeout, config.retries).await
            } else {
                Err(primary_err)
            }
        }
    }
}

async fn send_to_server(
    server: &RadiusServerConfig,
    req: &AccessRequest<'_>,
    timeout: Duration,
    retries: u8,
) -> Result<RadiusOutcome, RadiusError> {
    let addr = resolve_server(&server.host, server.port).await?;
    let bind_addr: SocketAddr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;

    let mut request_auth = [0u8; 16];
    let mut id_byte = [0u8; 1];
    {
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut request_auth);
        rng.fill_bytes(&mut id_byte);
    }
    let identifier = id_byte[0];
    let secret = server.secret.expose_secret().as_bytes();
    let packet_bytes = build_access_request(req, identifier, request_auth, secret)?;

    let attempts = retries.max(1);
    let mut buf = vec![0u8; MAX_PACKET_LEN];

    for attempt in 1..=attempts {
        socket.send(&packet_bytes).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                debug!("RADIUS attempt {attempt}/{attempts} to {addr} timed out");
                break;
            }
            match tokio::time::timeout(remaining, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    match verify_response(&buf[..len], identifier, &request_auth, secret) {
                        Ok(resp) => {
                            let reply_message = resp
                                .reply_message
                                .as_deref()
                                .and_then(sanitize_reply_message);
                            return Ok(match resp.decision {
                                Decision::Accept => RadiusOutcome::Accept { reply_message },
                                Decision::Reject => RadiusOutcome::Reject { reply_message },
                                Decision::Challenge => RadiusOutcome::Challenge {
                                    reply_message,
                                    state: resp.state.unwrap_or_default(),
                                },
                            });
                        }
                        Err(err) => {
                            // Silently discard forged, unsigned, or mismatched packets and keep
                            // waiting until the attempt deadline (RFC 2865 §3 + BlastRADIUS).
                            warn!("Ignoring invalid RADIUS response from {addr}: {err}");
                        }
                    }
                }
                Ok(Err(io_err)) => return Err(RadiusError::Io(io_err)),
                Err(_) => {
                    debug!("RADIUS attempt {attempt}/{attempts} to {addr} timed out");
                    break;
                }
            }
        }
    }

    Err(RadiusError::Timeout)
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr, RadiusError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    lookup_host((host, port))
        .await
        .map_err(|err| RadiusError::Resolve(format!("{host}:{port}: {err}")))?
        .next()
        .ok_or_else(|| RadiusError::Resolve(format!("{host}:{port}: no addresses found")))
}

/// Expose packet helpers for integration tests.
#[cfg(test)]
pub(crate) use super::packet::{
    Attribute, attr, build_response, code, decrypt_password, verify_request,
};
