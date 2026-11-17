//! Sign-in with the external provider through Edge: the enrollment portal and the OpenID steps
//! of the desktop client (VPN MFA and MFA configuration). New code, AGPL-3.0.
//!
//! The browser only talks to Edge, and Edge talks to Core over the bidi gRPC stream:
//!
//! 1. **Start:** Edge asks for an authorization URL (`AuthInfo`). Core starts the code flow with
//!    PKCE ([`flow::start`]) and keeps the state, nonce and PKCE verifier in memory, together with
//!    what the sign-in is for ([`Purpose`]). Edge gets the state and a separate random *binding*
//!    secret, and keeps both in an encrypted, HTTP-only cookie. The binding is never sent to the
//!    provider, so only the browser that started the sign-in holds it.
//! 2. **Callback:** the provider sends the browser back to Edge, which checks the state against
//!    its cookie, drops the cookie and forwards the code with the binding (and the state).
//! 3. **Finish:** Core takes the pending sign-in by its binding, once: it is removed whatever
//!    happens next. The state is compared again in constant time when Edge sends it, the code is
//!    exchanged with the PKCE verifier and the ID token is fully verified ([`flow::exchange`]).
//!
//! Pending sign-ins live for [`PENDING_TTL`]. The store is bounded overall and per client
//! address, evicting the oldest entries, so anonymous `AuthInfo` calls cannot grow it without
//! limit.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use url::Url;
use xguard_common::{
    db::{
        Id,
        models::{Settings, vpn_client_mfa_session::hash_token},
    },
    random::gen_alphanumeric,
    types::AuthFlowType,
};

use super::{
    constant_time_eq,
    flow::{self, FlowError, Identity, PendingLogin},
    provider::{ProviderConfig, ProviderKind, is_trusted_url},
};

/// How long a started sign-in can be finished.
pub const PENDING_TTL: Duration = Duration::from_secs(600);
/// Upper bound on sign-ins in progress, across all Edge instances.
const MAX_PENDING: usize = 10_000;
/// Upper bound on sign-ins in progress started from one client address.
const MAX_PENDING_PER_IP: usize = 20;
/// Length of the binding secret (about 238 bits of entropy).
const BINDING_LEN: usize = 40;
/// Limits on what Edge forwards from the browser.
const MAX_CODE_LEN: usize = 4096;
const MAX_STATE_LEN: usize = 512;

/// What a sign-in through Edge is for, decided when it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Enrollment portal: sign in to enroll, or to configure the desktop client.
    Enrollment,
    /// The OpenID step of a VPN MFA attempt.
    VpnMfa(VpnMfaTarget),
    /// Authorizing a desktop client's MFA configuration session.
    MfaConfig(MfaConfigTarget),
}

impl Purpose {
    fn flow(&self) -> AuthFlowType {
        match self {
            Self::Enrollment => AuthFlowType::Enrollment,
            Self::VpnMfa(_) | Self::MfaConfig(_) => AuthFlowType::Mfa,
        }
    }
}

/// The VPN MFA attempt an OpenID sign-in completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnMfaTarget {
    pub session_id: Id,
    pub token_hash: String,
    pub attempt_id: String,
    pub user_id: Id,
}

/// The MFA configuration attempt an OpenID sign-in authorizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfaConfigTarget {
    pub token_id: String,
    pub attempt_id: String,
    pub user_id: Id,
}

#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    /// Unknown, used or expired sign-in, or a state that does not match.
    #[error("The sign-in attempt expired or was already used; start again")]
    Expired,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Flow(#[from] FlowError),
}

/// What Edge needs to send the browser to the provider.
#[derive(Debug)]
pub struct EdgeAuthInfo {
    pub url: String,
    /// The OAuth `state`; Edge checks the callback against it.
    pub state: String,
    /// Kept by Edge in its cookie and sent back with the callback; never sent to the provider.
    pub binding: String,
    pub display_name: Option<String>,
    pub kind: ProviderKind,
}

struct Pending {
    created: Instant,
    ip: Option<IpAddr>,
    provider_id: Id,
    redirect_url: String,
    login: PendingLogin,
    purpose: Purpose,
}

#[derive(Default)]
struct Store {
    entries: HashMap<String, Pending>,
    per_ip: HashMap<IpAddr, usize>,
}

impl Store {
    fn remove(&mut self, key: &str) -> Option<Pending> {
        let pending = self.entries.remove(key)?;
        if let Some(ip) = pending.ip
            && let Some(count) = self.per_ip.get_mut(&ip)
        {
            *count -= 1;
            if *count == 0 {
                self.per_ip.remove(&ip);
            }
        }
        Some(pending)
    }

    fn prune(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.created) >= PENDING_TTL)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    fn evict_oldest(&mut self, ip: Option<IpAddr>) {
        let oldest = self
            .entries
            .iter()
            .filter(|(_, pending)| ip.is_none() || pending.ip == ip)
            .min_by_key(|(_, pending)| pending.created)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.remove(&key);
        }
    }

    fn insert(&mut self, key: String, pending: Pending, now: Instant) {
        if self.entries.len() >= MAX_PENDING {
            self.prune(now);
            if self.entries.len() >= MAX_PENDING {
                warn!("Too many OpenID sign-ins in progress; dropping the oldest");
                self.evict_oldest(None);
            }
        }
        if let Some(ip) = pending.ip {
            if self.per_ip.get(&ip).copied().unwrap_or_default() >= MAX_PENDING_PER_IP {
                self.prune(now);
                if self.per_ip.get(&ip).copied().unwrap_or_default() >= MAX_PENDING_PER_IP {
                    debug!("Too many OpenID sign-ins in progress from {ip}; dropping its oldest");
                    self.evict_oldest(Some(ip));
                }
            }
            *self.per_ip.entry(ip).or_default() += 1;
        }
        self.entries.insert(key, pending);
    }
}

static PENDING: LazyLock<Mutex<Store>> = LazyLock::new(Mutex::default);

fn store() -> std::sync::MutexGuard<'static, Store> {
    // A panic while holding the lock leaves the map consistent, so keep using it.
    PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Pending sign-ins are found by a hash of their binding, so the map never holds the secret.
fn binding_key(binding: &str) -> String {
    hash_token(binding)
}

/// The public Edge URL, which must be HTTPS (plain HTTP only to this machine, for testing).
pub fn edge_public_url() -> Result<Url, EdgeError> {
    let settings = Settings::get_current_settings();
    let raw = settings.public_proxy_url.trim();
    if raw.is_empty() {
        return Err(EdgeError::Config("The public Edge URL is not set".into()));
    }
    let url = Url::parse(raw)
        .map_err(|_| EdgeError::Config(format!("The public Edge URL {raw} is not valid")))?;
    if !is_trusted_url(&url) || url.query().is_some() || url.fragment().is_some() {
        return Err(EdgeError::Config(format!(
            "The public Edge URL {raw} must be an https:// URL without a query"
        )));
    }
    Ok(url)
}

/// Where the provider sends the browser back to: a page of the Edge web UI.
///
/// Register both `<edge>/openid/callback` and `<edge>/openid/mfa/callback` at the provider.
pub fn edge_redirect_url(flow: AuthFlowType) -> Result<String, EdgeError> {
    Ok(callback_url(edge_public_url()?, flow))
}

fn callback_url(mut url: Url, flow: AuthFlowType) -> String {
    let base = url.path().trim_end_matches('/').to_owned();
    let page = match flow {
        AuthFlowType::Enrollment => "openid/callback",
        AuthFlowType::Mfa => "openid/mfa/callback",
    };
    url.set_path(&format!("{base}/{page}"));
    url.to_string()
}

/// Whether users can sign in with the provider through Edge right now.
pub async fn available<'e, E: sqlx::PgExecutor<'e>>(executor: E) -> sqlx::Result<bool> {
    Ok(edge_public_url().is_ok() && ProviderConfig::enabled(executor).await?.is_some())
}

/// Starts a sign-in through Edge for `purpose`.
pub async fn start(
    config: &ProviderConfig,
    purpose: Purpose,
    ip: Option<IpAddr>,
) -> Result<EdgeAuthInfo, EdgeError> {
    let redirect_url = edge_redirect_url(purpose.flow())?;
    start_at(config, purpose, ip, redirect_url).await
}

/// [`start`] with the Edge callback URL given.
pub(crate) async fn start_at(
    config: &ProviderConfig,
    purpose: Purpose,
    ip: Option<IpAddr>,
    redirect_url: String,
) -> Result<EdgeAuthInfo, EdgeError> {
    let (url, login) = flow::start(config, &redirect_url).await?;
    let state = login.state.clone();
    let binding = gen_alphanumeric(BINDING_LEN);
    let now = Instant::now();
    store().insert(
        binding_key(&binding),
        Pending {
            created: now,
            ip,
            provider_id: config.provider.id,
            redirect_url,
            login,
            purpose,
        },
        now,
    );
    Ok(EdgeAuthInfo {
        url,
        state,
        binding,
        display_name: config.provider.display_name.clone(),
        kind: config.provider.kind,
    })
}

/// A sign-in through Edge that could not be finished, with what it was for when known.
#[derive(Debug)]
pub struct FinishError {
    pub error: EdgeError,
    pub purpose: Option<Purpose>,
}

impl From<EdgeError> for FinishError {
    fn from(error: EdgeError) -> Self {
        Self {
            error,
            purpose: None,
        }
    }
}

/// Finishes a sign-in through Edge and returns the verified identity with what it was for.
///
/// The pending sign-in is used up by this call, whatever its result. `state` is checked when
/// Edge sends it; Edge itself always checks it against its cookie.
pub async fn finish(
    config: &ProviderConfig,
    flow_type: AuthFlowType,
    binding: &str,
    state: Option<&str>,
    code: &str,
) -> Result<(Identity, Purpose), FinishError> {
    if binding.len() != BINDING_LEN || !binding.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(EdgeError::Expired.into());
    }
    if code.is_empty() || code.len() > MAX_CODE_LEN {
        return Err(EdgeError::Invalid("The authorization code is missing or too long").into());
    }
    if state.is_some_and(|state| state.len() > MAX_STATE_LEN) {
        return Err(EdgeError::Expired.into());
    }
    let pending = store()
        .remove(&binding_key(binding))
        .ok_or(EdgeError::Expired)?;
    if pending.created.elapsed() >= PENDING_TTL
        || pending.purpose.flow() != flow_type
        || pending.provider_id != config.provider.id
    {
        return Err(EdgeError::Expired.into());
    }
    let identity = match state {
        Some(state) => {
            flow::finish(config, &pending.redirect_url, pending.login, code, state).await
        }
        None => flow::exchange(config, &pending.redirect_url, pending.login, code).await,
    };
    match identity {
        Ok(identity) => Ok((identity, pending.purpose)),
        Err(FlowError::BadState) => Err(FinishError {
            error: EdgeError::Expired,
            purpose: Some(pending.purpose),
        }),
        Err(err) => Err(FinishError {
            error: EdgeError::Flow(err),
            purpose: Some(pending.purpose),
        }),
    }
}

/// Compares an expected identifier (attempt ID, subject) without leaking where it differs.
#[must_use]
pub fn same_secret(expected: &str, given: &str) -> bool {
    constant_time_eq(expected.as_bytes(), given.as_bytes())
}

/// `<token>.<attempt id>` from the desktop client's OpenID MFA link, or a bare token.
///
/// Both parts are alphanumeric and at most 64 characters, as Core issues them.
#[must_use]
pub fn parse_mfa_state(state: &str) -> Option<(&str, Option<&str>)> {
    let valid = |part: &str| {
        !part.is_empty() && part.len() <= 64 && part.bytes().all(|b| b.is_ascii_alphanumeric())
    };
    match state.split_once('.') {
        Some((token, attempt)) if valid(token) && valid(attempt) => Some((token, Some(attempt))),
        Some(_) => None,
        None if valid(state) => Some((state, None)),
        None => None,
    }
}

/// Who an identity belongs to, for the MFA checks: only the linked subject counts.
#[must_use]
pub fn subject_matches(linked_subject: Option<&str>, identity: &Identity) -> bool {
    linked_subject.is_some_and(|subject| same_secret(subject, &identity.subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(created: Instant, ip: Option<IpAddr>) -> Pending {
        Pending {
            created,
            ip,
            provider_id: 1,
            redirect_url: String::new(),
            login: PendingLogin {
                state: String::new(),
                nonce: String::new(),
                verifier: String::new(),
            },
            purpose: Purpose::Enrollment,
        }
    }

    #[test]
    fn store_is_bounded_per_address() {
        let mut store = Store::default();
        let now = Instant::now();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let first = binding_key("first");
        store.insert(first.clone(), pending(now, Some(ip)), now);
        for n in 0..MAX_PENDING_PER_IP {
            let later = now + Duration::from_millis(n as u64 + 1);
            store.insert(
                binding_key(&format!("b{n}")),
                pending(later, Some(ip)),
                later,
            );
        }
        // The oldest sign-in of that address made room for the newest.
        assert_eq!(store.entries.len(), MAX_PENDING_PER_IP);
        assert!(!store.entries.contains_key(&first));
        assert_eq!(store.per_ip[&ip], MAX_PENDING_PER_IP);
        // Another address is not affected.
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        store.insert(binding_key("other"), pending(now, Some(other)), now);
        assert_eq!(store.entries.len(), MAX_PENDING_PER_IP + 1);
        // Removing keeps the counts right.
        assert!(store.remove(&binding_key("other")).is_some());
        assert!(!store.per_ip.contains_key(&other));
    }

    #[test]
    fn store_prunes_expired_entries() {
        let mut store = Store::default();
        let start = Instant::now();
        store.insert(binding_key("old"), pending(start, None), start);
        let later = start + PENDING_TTL;
        store.prune(later);
        assert!(store.entries.is_empty());
    }

    #[test]
    fn callback_urls_keep_the_edge_path() {
        let url = |raw: &str, flow| callback_url(Url::parse(raw).unwrap(), flow);
        assert_eq!(
            url("https://edge.example.org", AuthFlowType::Enrollment),
            "https://edge.example.org/openid/callback"
        );
        assert_eq!(
            url("https://edge.example.org/", AuthFlowType::Mfa),
            "https://edge.example.org/openid/mfa/callback"
        );
        assert_eq!(
            url("https://example.org/vpn/", AuthFlowType::Mfa),
            "https://example.org/vpn/openid/mfa/callback"
        );
    }

    #[test]
    fn mfa_state_parsing() {
        assert_eq!(parse_mfa_state("abc"), Some(("abc", None)));
        assert_eq!(parse_mfa_state("abc.def"), Some(("abc", Some("def"))));
        assert_eq!(parse_mfa_state("abc."), None);
        assert_eq!(parse_mfa_state(".def"), None);
        assert_eq!(parse_mfa_state("a.b.c"), None);
        assert_eq!(parse_mfa_state("a b"), None);
        assert_eq!(parse_mfa_state(&"a".repeat(65)), None);
        assert_eq!(parse_mfa_state(""), None);
    }

    #[test]
    fn subjects_must_match_exactly() {
        let identity = Identity {
            subject: "sub-1".into(),
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            preferred_username: None,
            phone: None,
        };
        assert!(subject_matches(Some("sub-1"), &identity));
        assert!(!subject_matches(Some("sub-12"), &identity));
        assert!(!subject_matches(Some("SUB-1"), &identity));
        assert!(!subject_matches(None, &identity));
    }
}
