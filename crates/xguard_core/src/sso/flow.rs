//! The OpenID Connect authorization code flow, with PKCE.
//!
//! - **Start:** XGuard builds the authorization URL. It keeps the state, nonce and PKCE verifier
//!   in an encrypted, HTTP-only cookie that lasts 10 minutes, so nothing is stored server-side.
//! - **Finish:** the state must match (compared in constant time) and the cookie is single-use.
//!   The code is exchanged with the PKCE verifier. The ID token's signature, issuer, audience,
//!   expiry and nonce are all checked.
//! - **Discovery:** provider metadata and signing keys are cached for 10 minutes, so sign-ins do
//!   not each fetch them. A token signed with an unknown key refreshes the cache once.
//! - **No redirects:** HTTP requests to the provider do not follow redirects, so a provider
//!   cannot point XGuard at internal addresses.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use openidconnect::{
    AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, TokenResponse,
    core::{CoreClient, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType},
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::provider::{ProviderConfig, is_trusted_url, resolve_and_validate_host};

const METADATA_TTL: Duration = Duration::from_secs(600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OIDC_BODY_BYTES: usize = 1024 * 1024;
const PENDING_LOGIN_TTL_SECS: i64 = 600;

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("The OpenID provider could not be reached or described itself wrongly: {0}")]
    Discovery(String),
    #[error("The sign-in attempt expired or was started in another browser; try again")]
    BadState,
    #[error("The OpenID provider refused the sign-in: {0}")]
    Exchange(String),
    #[error("The identity token could not be verified: {0}")]
    Token(String),
    #[error("Invalid OpenID provider settings: {0}")]
    Config(String),
}

/// What the browser keeps between start and finish (encrypted).
#[derive(Serialize, Deserialize)]
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
}

/// Who the provider says signed in.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub preferred_username: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum SafeHttpError {
    #[error("untrusted OpenID URL")]
    UntrustedUrl,
    #[error("invalid HTTP request: {0}")]
    InvalidRequest(String),
    #[error("OpenID response exceeded {MAX_OIDC_BODY_BYTES} bytes")]
    ResponseTooLarge,
    #[error("HTTP request failed: {0}")]
    Transport(#[from] openidconnect::reqwest::Error),
    #[error("HTTP response build failed: {0}")]
    ResponseBuild(#[from] openidconnect::http::Error),
}

struct SafeHttpClient(openidconnect::reqwest::Client);

impl<'c> AsyncHttpClient<'c> for SafeHttpClient {
    type Error = SafeHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let uri = request.uri().to_string();
            let url =
                Url::parse(&uri).map_err(|err| SafeHttpError::InvalidRequest(err.to_string()))?;
            if !is_trusted_url(&url) {
                return Err(SafeHttpError::UntrustedUrl);
            }
            let req: openidconnect::reqwest::Request = request.try_into()?;
            let mut response = self.0.execute(req).await?;
            let mut builder = openidconnect::http::Response::builder()
                .status(response.status())
                .version(response.version());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            if let Some(len) = response.content_length()
                && len > MAX_OIDC_BODY_BYTES as u64
            {
                return Err(SafeHttpError::ResponseTooLarge);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len().saturating_add(chunk.len()) > MAX_OIDC_BODY_BYTES {
                    return Err(SafeHttpError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            builder.body(body).map_err(SafeHttpError::ResponseBuild)
        })
    }
}

struct SafeDnsResolver;

impl openidconnect::reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(
        &self,
        name: openidconnect::reqwest::dns::Name,
    ) -> openidconnect::reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolve_and_validate_host(&host).await?;
            Ok(Box::new(addrs.into_iter()) as openidconnect::reqwest::dns::Addrs)
        })
    }
}

pub(crate) fn http_client() -> Result<openidconnect::reqwest::Client, FlowError> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(SafeDnsResolver))
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|err| FlowError::Config(err.to_string()))
}

static METADATA: LazyLock<Mutex<HashMap<String, (Instant, CoreProviderMetadata)>>> =
    LazyLock::new(Mutex::default);

async fn metadata(issuer: &str, refresh: bool) -> Result<CoreProviderMetadata, FlowError> {
    if !refresh
        && let Some((fetched, metadata)) = METADATA
            .lock()
            .ok()
            .and_then(|cache| cache.get(issuer).cloned())
        && fetched.elapsed() < METADATA_TTL
    {
        return Ok(metadata);
    }
    let parsed_issuer = Url::parse(issuer).map_err(|err| FlowError::Config(err.to_string()))?;
    if !is_trusted_url(&parsed_issuer) {
        return Err(FlowError::Config("The issuer URL is not trusted".into()));
    }
    let issuer_url =
        IssuerUrl::new(issuer.to_owned()).map_err(|err| FlowError::Config(err.to_string()))?;
    let http = SafeHttpClient(http_client()?);
    let metadata = CoreProviderMetadata::discover_async(issuer_url, &http)
        .await
        .map_err(|err| FlowError::Discovery(error_chain(&err)))?;
    if !has_trusted_discovery_endpoints(&parsed_issuer, &metadata) {
        return Err(FlowError::Discovery(
            "the provider metadata contained an untrusted endpoint URL".into(),
        ));
    }
    if let Ok(mut cache) = METADATA.lock() {
        cache.insert(issuer.to_owned(), (Instant::now(), metadata.clone()));
    }
    Ok(metadata)
}

pub(super) fn has_trusted_discovery_endpoints(
    issuer: &Url,
    metadata: &CoreProviderMetadata,
) -> bool {
    let https_only = issuer.scheme() == "https";
    let valid_endpoint =
        |url: &Url| is_trusted_url(url) && (!https_only || url.scheme() == "https");
    valid_endpoint(metadata.authorization_endpoint().url())
        && metadata
            .token_endpoint()
            .is_none_or(|endpoint| valid_endpoint(endpoint.url()))
        && valid_endpoint(metadata.jwks_uri().url())
}

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

async fn client(
    config: &ProviderConfig,
    redirect_url: &str,
    refresh: bool,
) -> Result<
    CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
    FlowError,
> {
    let metadata = metadata(&config.provider.issuer, refresh).await?;
    let redirect = RedirectUrl::new(redirect_url.to_owned())
        .map_err(|err| FlowError::Config(err.to_string()))?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.provider.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(redirect))
}

/// Checks that the provider can be discovered with these settings.
pub async fn check(config: &ProviderConfig) -> Result<(), FlowError> {
    metadata(&config.provider.issuer, true).await.map(|_| ())
}

/// Builds the URL to send the browser to, and what to keep until it comes back.
pub async fn start(
    config: &ProviderConfig,
    redirect_url: &str,
) -> Result<(String, PendingLogin), FlowError> {
    let client = client(config, redirect_url, false).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(challenge)
        .url();
    Ok((
        url.to_string(),
        PendingLogin {
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            verifier: verifier.secret().clone(),
            expires_at: Utc::now().timestamp() + PENDING_LOGIN_TTL_SECS,
            issuer: config.provider.issuer.clone(),
            client_id: config.provider.client_id.clone(),
        },
    ))
}

/// Completes the sign-in and returns the verified identity.
pub async fn finish(
    config: &ProviderConfig,
    redirect_url: &str,
    pending: PendingLogin,
    code: &str,
    state: &str,
) -> Result<Identity, FlowError> {
    if Utc::now().timestamp() > pending.expires_at
        || pending.issuer != config.provider.issuer
        || pending.client_id != config.provider.client_id
        || !super::constant_time_eq(pending.state.as_bytes(), state.as_bytes())
    {
        return Err(FlowError::BadState);
    }
    exchange(config, redirect_url, pending, code).await
}

/// Exchanges the code with the PKCE verifier and verifies the ID token.
///
/// The caller must already have matched the returned `state` to `pending` (see [`finish`]).
pub(crate) async fn exchange(
    config: &ProviderConfig,
    redirect_url: &str,
    pending: PendingLogin,
    code: &str,
) -> Result<Identity, FlowError> {
    let client = client(config, redirect_url, false).await?;
    let http = SafeHttpClient(http_client()?);
    let response = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|err| FlowError::Config(err.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
        .request_async(&http)
        .await
        .map_err(|err| FlowError::Exchange(error_chain(&err)))?;
    let id_token = response
        .id_token()
        .ok_or_else(|| FlowError::Token("the provider returned no ID token".into()))?;
    let nonce = Nonce::new(pending.nonce);
    let claims: CoreIdTokenClaims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(claims) => claims.clone(),
        Err(first) => {
            // The provider may have rotated its keys: refresh them once and try again.
            let refreshed = self::client(config, redirect_url, true).await?;
            id_token
                .claims(&refreshed.id_token_verifier(), &nonce)
                .map_err(|_| FlowError::Token(first.to_string()))?
                .clone()
        }
    };
    Ok(identity(&claims))
}

fn identity(claims: &CoreIdTokenClaims) -> Identity {
    let localized =
        |value: Option<&openidconnect::LocalizedClaim<openidconnect::EndUserGivenName>>| {
            value
                .and_then(|claim| claim.get(None))
                .map(|name| name.to_string())
        };
    Identity {
        subject: claims.subject().to_string(),
        email: claims.email().map(|email| email.to_string()),
        email_verified: claims.email_verified().unwrap_or(false),
        first_name: localized(claims.given_name()),
        last_name: claims
            .family_name()
            .and_then(|claim| claim.get(None))
            .map(|name| name.to_string()),
        preferred_username: claims.preferred_username().map(|name| name.to_string()),
        phone: claims.phone_number().map(|phone| phone.to_string()),
    }
}
