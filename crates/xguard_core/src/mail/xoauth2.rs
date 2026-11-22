//! OAuth 2.0 (SMTP AUTH XOAUTH2) for the SMTP server: Google Workspace / Gmail and
//! Microsoft 365. New code, AGPL-3.0.
//!
//! - **Connecting a mailbox:** an admin starts an authorization code flow with PKCE (S256) and
//!   a random state ([`start`]). XGuard keeps the PKCE verifier, the state and the client secret
//!   server-side, bound to that admin, for 10 minutes, at most [`MAX_PENDING`] at a time. The
//!   provider sends the browser back to `<XGuard URL>/smtp-oauth-callback`; the web UI hands the
//!   code and state to [`finish`], which compares the state in constant time, exchanges the code
//!   (with the verifier and the client secret, server to server) and stores the refresh token.
//! - **Secrets stay on the server:** the client secret and refresh token are never returned by
//!   the API (only `*_set` flags), never logged, and cannot be set through the settings API.
//! - **Sending mail:** [`access_token`] returns a cached access token, refreshed with the refresh
//!   token when it is missing or expires within [`EXPIRY_MARGIN`]. One refresh at a time: mails
//!   sent together wait for the same refresh. A rotated refresh token is saved.
//! - **HTTP:** token requests go to the provider's fixed HTTPS endpoints, do not follow
//!   redirects and time out after [`HTTP_TIMEOUT`]. Errors name the provider's error code and
//!   description, so admins can tell a revoked grant from a wrong client secret.

use std::{
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use openidconnect::{CsrfToken, PkceCodeChallenge};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use xguard_common::db::{
    Id,
    models::{
        Settings,
        settings::{
            SettingsSaveError,
            smtp::{SmtpAuthentication, SmtpEncryption, SmtpSettings},
            update_current_settings, update_smtp_oauth_refresh_token,
        },
    },
};

pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const MICROSOFT_LOGIN: &str = "https://login.microsoftonline.com";
/// The web UI route the provider sends the browser back to.
pub const CALLBACK_PATH: &str = "/smtp-oauth-callback";

/// How long a started authorization may take.
const PENDING_TTL: Duration = Duration::from_secs(600);
/// Most authorizations in progress at a time; the oldest is dropped when another starts.
pub const MAX_PENDING: usize = 16;
/// An access token is refreshed when it expires within this margin.
pub const EXPIRY_MARGIN: Duration = Duration::from_secs(120);
/// Assumed lifetime when the provider does not say (both document one hour).
const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ERROR_LEN: usize = 300;

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("SMTP OAuth is not configured: {0}")]
    NotConfigured(&'static str),
    #[error("Invalid SMTP OAuth settings: {0}")]
    Invalid(String),
    #[error("The authorization expired or was started by someone else; connect the mailbox again")]
    BadState,
    #[error("The provider refused the authorization: {0}")]
    Denied(String),
    #[error(
        "The provider refused the token request ({0}); check the client ID and secret, or \
         connect the mailbox again in the SMTP settings"
    )]
    Provider(String),
    #[error(
        "The provider did not return a refresh token; remove XGuard's access in the account settings and connect again"
    )]
    NoRefreshToken,
    #[error("The provider could not be reached: {0}")]
    Http(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<SettingsSaveError> for OAuthError {
    fn from(err: SettingsSaveError) -> Self {
        match err {
            SettingsSaveError::Db(err) => Self::Database(err),
            SettingsSaveError::Validation(err) => Self::Invalid(err.to_string()),
        }
    }
}

/// Mail providers XGuard can authorize with.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
    Microsoft,
}

/// Where a provider's authorization and token endpoints are.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub authorize: Url,
    pub token: Url,
}

impl Provider {
    /// The provider of stored settings, from the issuer URL (the settings' existing contract:
    /// `https://accounts.google.com` or `https://login.microsoftonline.com/<tenant>`).
    #[must_use]
    pub fn from_issuer(issuer: &str) -> Option<Self> {
        let issuer = issuer.trim().trim_end_matches('/');
        if issuer == GOOGLE_ISSUER {
            Some(Self::Google)
        } else if issuer == MICROSOFT_LOGIN || issuer.starts_with(&format!("{MICROSOFT_LOGIN}/")) {
            Some(Self::Microsoft)
        } else {
            None
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Microsoft => "Microsoft 365",
        }
    }

    fn issuer(self, tenant: &str) -> String {
        match self {
            Self::Google => GOOGLE_ISSUER.into(),
            Self::Microsoft => format!("{MICROSOFT_LOGIN}/{tenant}"),
        }
    }

    fn scope(self) -> &'static str {
        match self {
            // Gmail's SMTP needs the full mail scope.
            Self::Google => "https://mail.google.com/",
            Self::Microsoft => "https://outlook.office.com/SMTP.Send offline_access",
        }
    }

    /// The provider's SMTP submission server (STARTTLS on 587).
    #[must_use]
    pub fn smtp_server(self) -> &'static str {
        match self {
            Self::Google => "smtp.gmail.com",
            Self::Microsoft => "smtp.office365.com",
        }
    }

    fn endpoints(self, tenant: &str) -> Endpoints {
        #[cfg(test)]
        if let Some(endpoints) = tests::endpoint_override() {
            return endpoints;
        }
        let (authorize, token) = match self {
            Self::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
                "https://oauth2.googleapis.com/token".to_owned(),
            ),
            Self::Microsoft => (
                format!("{MICROSOFT_LOGIN}/{tenant}/oauth2/v2.0/authorize"),
                format!("{MICROSOFT_LOGIN}/{tenant}/oauth2/v2.0/token"),
            ),
        };
        Endpoints {
            authorize: Url::parse(&authorize).expect("valid provider URL"),
            token: Url::parse(&token).expect("valid provider URL"),
        }
    }
}

/// Microsoft tenant: a GUID, a domain, or `common` / `organizations`.
fn valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 64
        && tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn valid_client_id(client_id: &str) -> bool {
    !client_id.is_empty()
        && client_id.len() <= 256
        && client_id.bytes().all(|b| b.is_ascii_graphic())
}

fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The redirect URI registered at the provider: the XGuard URL with [`CALLBACK_PATH`]. Must be
/// HTTPS, or plain HTTP on this machine (for testing).
pub fn redirect_uri(xguard_url: &str) -> Result<Url, OAuthError> {
    let base = Url::parse(xguard_url.trim())
        .map_err(|_| OAuthError::Invalid("the XGuard URL is not a valid URL".into()))?;
    let loopback = base.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
        return Err(OAuthError::Invalid(
            "the XGuard URL must use HTTPS for the OAuth redirect".into(),
        ));
    }
    let path = format!("{}{CALLBACK_PATH}", base.path().trim_end_matches('/'));
    let mut url = base;
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// What an admin submits to connect a mailbox.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StartRequest {
    pub provider: Provider,
    pub client_id: String,
    /// Leave out to keep the stored secret (only with the same client ID).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Microsoft only: the directory (tenant) ID or domain; `organizations` by default.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The mailbox to send from; also the XOAUTH2 user.
    pub sender: String,
    #[serde(default = "default_true")]
    pub tls_verify_cert: bool,
}

fn default_true() -> bool {
    true
}

struct Pending {
    state: String,
    admin_id: Id,
    started: Instant,
    verifier: String,
    redirect_uri: Url,
    provider: Provider,
    tenant: String,
    client_id: String,
    client_secret: SecretString,
    sender: String,
    tls_verify_cert: bool,
}

static PENDING: LazyLock<Mutex<Vec<Pending>>> = LazyLock::new(Mutex::default);

/// Starts connecting a mailbox. Returns the provider URL to open (in a popup).
pub fn start(admin_id: Id, request: StartRequest, settings: &Settings) -> Result<Url, OAuthError> {
    let client_id = request.client_id.trim().to_owned();
    if !valid_client_id(&client_id) {
        return Err(OAuthError::Invalid("client ID".into()));
    }
    let sender = request.sender.trim().to_owned();
    if !valid_email(&sender) {
        return Err(OAuthError::Invalid("sender email address".into()));
    }
    let tenant = match request.provider {
        Provider::Google => String::new(),
        Provider::Microsoft => {
            let tenant = request
                .tenant_id
                .as_deref()
                .map(str::trim)
                .filter(|tenant| !tenant.is_empty())
                .unwrap_or("organizations");
            if !valid_tenant(tenant) {
                return Err(OAuthError::Invalid("tenant ID".into()));
            }
            tenant.to_owned()
        }
    };
    let client_secret = match request.client_secret.map(|secret| secret.trim().to_owned()) {
        Some(secret) if !secret.is_empty() => {
            if secret.len() > 1024 {
                return Err(OAuthError::Invalid("client secret".into()));
            }
            SecretString::from(secret)
        }
        // Reuse the stored secret only when the provider, tenant, and client ID match.
        _ => {
            let stored_provider = settings
                .smtp
                .oauth_issuer_url
                .as_deref()
                .and_then(Provider::from_issuer);
            let stored_tenant = settings
                .smtp
                .oauth_tenant_id
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .unwrap_or("organizations");
            let same_tenant = request.provider != Provider::Microsoft || stored_tenant == tenant;
            match (
                &settings.smtp.oauth_client_secret,
                &settings.smtp.oauth_client_id,
            ) {
                (Some(secret), Some(stored_id))
                    if *stored_id == client_id
                        && stored_provider == Some(request.provider)
                        && same_tenant =>
                {
                    SecretString::from(secret.expose_secret().to_owned())
                }
                _ => return Err(OAuthError::NotConfigured("client secret")),
            }
        }
    };
    let redirect_uri = redirect_uri(&settings.xguard_url)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random_len(32).secret().clone();

    let endpoints = request.provider.endpoints(&tenant);
    let mut url = endpoints.authorize;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("scope", request.provider.scope())
            .append_pair("state", &state)
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256")
            .append_pair("login_hint", &sender);
        match request.provider {
            // A refresh token is only issued for offline access, and only on consent.
            Provider::Google => {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            }
            Provider::Microsoft => {
                query.append_pair("prompt", "select_account");
            }
        }
    }

    let mut pending = PENDING.lock().expect("pending SMTP authorizations");
    pending.retain(|entry| entry.started.elapsed() < PENDING_TTL && entry.admin_id != admin_id);
    if pending.len() >= MAX_PENDING {
        pending.remove(0);
    }
    pending.push(Pending {
        state,
        admin_id,
        started: Instant::now(),
        verifier: verifier.secret().clone(),
        redirect_uri,
        provider: request.provider,
        tenant,
        client_id,
        client_secret,
        sender,
        tls_verify_cert: request.tls_verify_cert,
    });
    Ok(url)
}

/// Takes the authorization `admin_id` started with `state`. It works once: it is removed
/// whatever happens next.
fn take_pending(admin_id: Id, state: &str) -> Result<Pending, OAuthError> {
    let mut pending = PENDING.lock().expect("pending SMTP authorizations");
    pending.retain(|entry| entry.started.elapsed() < PENDING_TTL);
    let index = pending
        .iter()
        .position(|entry| crate::sso::constant_time_eq(entry.state.as_bytes(), state.as_bytes()))
        .ok_or(OAuthError::BadState)?;
    let entry = pending.remove(index);
    if entry.admin_id != admin_id {
        return Err(OAuthError::BadState);
    }
    Ok(entry)
}

/// The result of connecting a mailbox.
#[derive(Debug)]
pub struct Connected {
    pub provider: Provider,
    pub sender: String,
}

/// Finishes connecting a mailbox: exchanges the code and saves the SMTP settings (server,
/// XOAUTH2, client, refresh token). `error` is the provider's `error` parameter, if the
/// browser came back with one.
pub async fn finish(
    pool: &PgPool,
    admin_id: Id,
    state: &str,
    code: Option<&str>,
    error: Option<&str>,
) -> Result<Connected, OAuthError> {
    if state.is_empty() || state.len() > 512 {
        return Err(OAuthError::BadState);
    }
    let pending = take_pending(admin_id, state)?;
    if let Some(error) = error {
        return Err(OAuthError::Denied(sanitize(error)));
    }
    let code = code
        .filter(|code| !code.is_empty() && code.len() <= 4096)
        .ok_or_else(|| OAuthError::Invalid("missing authorization code".into()))?;

    let endpoints = pending.provider.endpoints(&pending.tenant);
    let response = token_request(
        &endpoints.token,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", pending.redirect_uri.as_str()),
            ("client_id", &pending.client_id),
            ("client_secret", pending.client_secret.expose_secret()),
            ("code_verifier", &pending.verifier),
        ],
    )
    .await?;
    let refresh_token = response
        .refresh_token
        .clone()
        .filter(|token| !token.is_empty())
        .ok_or(OAuthError::NoRefreshToken)?;

    let mut settings = Settings::get_current_settings();
    let smtp = &mut settings.smtp;
    smtp.server = Some(pending.provider.smtp_server().into());
    smtp.port = Some(587);
    smtp.encryption = SmtpEncryption::StartTls;
    smtp.tls_verify_cert = pending.tls_verify_cert;
    smtp.sender = Some(pending.sender.clone());
    smtp.user = None;
    smtp.password = None;
    smtp.authentication = SmtpAuthentication::XOAuth2;
    smtp.oauth_issuer_url = Some(pending.provider.issuer(&pending.tenant));
    smtp.oauth_tenant_id =
        (pending.provider == Provider::Microsoft).then(|| pending.tenant.clone());
    smtp.oauth_client_id = Some(pending.client_id.clone());
    smtp.oauth_client_secret = Some(pending.client_secret.expose_secret().to_owned().into());
    smtp.oauth_refresh_token = Some(refresh_token.clone().into());
    let smtp = smtp.clone();
    update_current_settings(pool, settings).await?;
    register_pool(pool);
    cache_token(&smtp, &response);
    info!(
        "Connected the SMTP mailbox {} with {} (XOAUTH2)",
        pending.sender,
        pending.provider.name()
    );
    Ok(Connected {
        provider: pending.provider,
        sender: pending.sender,
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Keeps provider text printable and short.
fn sanitize(text: &str) -> String {
    let mut clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.len() > MAX_ERROR_LEN {
        let mut end = MAX_ERROR_LEN;
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        clean.truncate(end);
        clean.push('…');
    }
    clean
}

fn http_client() -> Result<reqwest::Client, OAuthError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|err| OAuthError::Http(err.to_string()))
}

async fn token_request(
    token_url: &Url,
    form: &[(&str, &str)],
) -> Result<TokenResponse, OAuthError> {
    let response = http_client()?
        .post(token_url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(|err| OAuthError::Http(sanitize(&err.without_url().to_string())))?;
    let status = response.status();
    // Token responses are small; refuse anything large.
    let body = response
        .bytes()
        .await
        .map_err(|err| OAuthError::Http(sanitize(&err.without_url().to_string())))?;
    if body.len() > 64 * 1024 {
        return Err(OAuthError::Http("oversized token response".into()));
    }
    if status.is_success() {
        let token: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| OAuthError::Http("unexpected token response".into()))?;
        if token.access_token.is_empty() {
            return Err(OAuthError::Http("empty access token".into()));
        }
        return Ok(token);
    }
    match serde_json::from_slice::<TokenErrorResponse>(&body) {
        Ok(error) => {
            let mut message = sanitize(&error.error);
            if let Some(description) = error.error_description {
                message = format!("{message}: {}", sanitize(&description));
            }
            Err(OAuthError::Provider(message))
        }
        Err(_) => Err(OAuthError::Provider(format!("HTTP {status}"))),
    }
}

struct CachedToken {
    client_id: String,
    refresh_token: String,
    access_token: SecretString,
    expires_at: Instant,
}

static CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);
/// One refresh at a time.
static REFRESH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// For saving rotated refresh tokens.
static POOL: Mutex<Option<PgPool>> = Mutex::new(None);

/// Lets the mailer save refresh tokens the provider rotates. Called at startup.
pub fn register_pool(pool: &PgPool) {
    if let Ok(mut slot) = POOL.lock() {
        *slot = Some(pool.clone());
    }
}

/// Forgets the cached access token (after the SMTP settings change).
pub fn clear_cache() {
    if let Ok(mut cache) = CACHE.lock() {
        *cache = None;
    }
}

fn cache_token(smtp: &SmtpSettings, response: &TokenResponse) {
    let (Some(client_id), Some(refresh_token)) = (&smtp.oauth_client_id, &smtp.oauth_refresh_token)
    else {
        return;
    };
    let lifetime = response
        .expires_in
        .map_or(DEFAULT_LIFETIME, Duration::from_secs)
        .min(Duration::from_secs(24 * 3600));
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some(CachedToken {
            client_id: client_id.clone(),
            refresh_token: refresh_token.expose_secret().to_owned(),
            access_token: SecretString::from(response.access_token.clone()),
            expires_at: Instant::now() + lifetime,
        });
    }
}

fn cached(client_id: &str, refresh_token: &str) -> Option<String> {
    let cache = CACHE.lock().ok()?;
    let entry = cache.as_ref()?;
    (entry.client_id == client_id
        && crate::sso::constant_time_eq(entry.refresh_token.as_bytes(), refresh_token.as_bytes())
        && entry.expires_at > Instant::now() + EXPIRY_MARGIN)
        .then(|| entry.access_token.expose_secret().to_owned())
}

/// An access token for SMTP AUTH XOAUTH2 with `smtp`, from the cache or refreshed.
pub async fn access_token(smtp: &SmtpSettings) -> Result<String, OAuthError> {
    let issuer = smtp
        .oauth_issuer_url
        .as_deref()
        .ok_or(OAuthError::NotConfigured("provider"))?;
    let provider = Provider::from_issuer(issuer)
        .ok_or_else(|| OAuthError::Invalid(format!("unsupported provider {}", sanitize(issuer))))?;
    let client_id = smtp
        .oauth_client_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or(OAuthError::NotConfigured("client ID"))?;
    let client_secret = smtp
        .oauth_client_secret
        .as_ref()
        .ok_or(OAuthError::NotConfigured("client secret"))?;
    let refresh_token = smtp
        .oauth_refresh_token
        .as_ref()
        .map(|token| token.expose_secret().to_owned())
        .filter(|token| !token.is_empty())
        .ok_or(OAuthError::NotConfigured(
            "mailbox; connect it in the SMTP settings",
        ))?;
    if let Some(token) = cached(client_id, &refresh_token) {
        return Ok(token);
    }
    let _guard = REFRESH.lock().await;
    // Another mail may have refreshed (and rotated the refresh token) while this one waited.
    let latest_smtp = Settings::get_current_settings().smtp;
    let effective_refresh = if latest_smtp.authentication == SmtpAuthentication::XOAuth2
        && latest_smtp.oauth_client_id.as_deref() == Some(client_id)
        && latest_smtp.oauth_issuer_url.as_deref() == Some(issuer)
    {
        latest_smtp
            .oauth_refresh_token
            .as_ref()
            .map(|token| token.expose_secret().to_owned())
            .filter(|token| !token.is_empty())
            .unwrap_or_else(|| refresh_token.clone())
    } else {
        refresh_token.clone()
    };
    if let Some(token) = cached(client_id, &effective_refresh) {
        return Ok(token);
    }
    let tenant = smtp
        .oauth_tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|tenant| valid_tenant(tenant))
        .or_else(|| {
            issuer
                .trim_end_matches('/')
                .strip_prefix(&format!("{MICROSOFT_LOGIN}/"))
                .filter(|tenant| valid_tenant(tenant))
        })
        .unwrap_or("organizations");
    let endpoints = provider.endpoints(tenant);
    debug!("Refreshing the SMTP OAuth access token");
    let response = token_request(
        &endpoints.token,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &effective_refresh),
            ("client_id", client_id),
            ("client_secret", client_secret.expose_secret()),
            ("scope", provider.scope()),
        ],
    )
    .await
    .inspect_err(|err| warn!("Failed to refresh the SMTP OAuth access token: {err}"))?;

    let mut current = smtp.clone();
    current.oauth_refresh_token = Some(effective_refresh.clone().into());
    if let Some(rotated) = response
        .refresh_token
        .as_deref()
        .filter(|rotated| !rotated.is_empty() && *rotated != effective_refresh)
    {
        current.oauth_refresh_token = Some(rotated.to_owned().into());
        save_rotated_refresh_token(&effective_refresh, rotated).await;
    }
    cache_token(&current, &response);
    Ok(response.access_token)
}

/// Saves a refresh token the provider rotated, unless the mailbox was reconnected meanwhile.
async fn save_rotated_refresh_token(previous: &str, rotated: &str) {
    let pool = POOL.lock().ok().and_then(|slot| slot.clone());
    let Some(pool) = pool else {
        warn!("The SMTP OAuth refresh token was rotated but cannot be saved yet");
        return;
    };
    if let Err(err) = update_smtp_oauth_refresh_token(&pool, previous, rotated).await {
        error!("Failed to save the rotated SMTP OAuth refresh token: {err}");
    }
}

/// Keeps the server-managed XOAUTH2 secrets of `before` in settings an admin submitted: the
/// refresh token only comes from [`finish`]. It is dropped (the mailbox must be connected again)
/// when switching to or between XOAUTH2 grants, and both OAuth secrets are dropped when leaving
/// XOAUTH2.
pub fn protect_settings(before: &SmtpSettings, after: &mut SmtpSettings) {
    // Never accept a caller-supplied refresh token; only allow keeping `before`'s or clearing to None.
    let kept_refresh = match (&before.oauth_refresh_token, &after.oauth_refresh_token) {
        (_, None) => None,
        (Some(prev), Some(_)) => Some(prev.clone()),
        (None, Some(_)) => None,
    };
    if before.authentication == SmtpAuthentication::XOAuth2
        && after.authentication != SmtpAuthentication::XOAuth2
    {
        after.oauth_refresh_token = None;
        after.oauth_client_secret = None;
    } else if after.authentication == SmtpAuthentication::XOAuth2 {
        let same_client = before.authentication == SmtpAuthentication::XOAuth2
            && after.oauth_client_id == before.oauth_client_id
            && after.oauth_issuer_url == before.oauth_issuer_url
            && after.oauth_tenant_id == before.oauth_tenant_id;
        if !same_client && after.oauth_client_secret == before.oauth_client_secret {
            after.oauth_client_secret = None;
        }
        let same_grant = same_client
            && after.server == before.server
            && after.port == before.port
            && after.sender == before.sender
            && after.encryption == before.encryption;
        after.oauth_refresh_token = if same_grant { kept_refresh } else { None };
    } else {
        after.oauth_refresh_token = kept_refresh;
    }
    if *before != *after {
        clear_cache();
    }
}

#[cfg(test)]
pub(crate) mod tests;
