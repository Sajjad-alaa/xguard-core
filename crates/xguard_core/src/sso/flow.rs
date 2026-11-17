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
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType},
};
use serde::{Deserialize, Serialize};

use super::provider::ProviderConfig;

const METADATA_TTL: Duration = Duration::from_secs(600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

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

pub(crate) fn http_client() -> Result<openidconnect::reqwest::Client, FlowError> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
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
    let issuer_url =
        IssuerUrl::new(issuer.to_owned()).map_err(|err| FlowError::Config(err.to_string()))?;
    let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client()?)
        .await
        .map_err(|err| FlowError::Discovery(error_chain(&err)))?;
    if let Ok(mut cache) = METADATA.lock() {
        cache.insert(issuer.to_owned(), (Instant::now(), metadata.clone()));
    }
    Ok(metadata)
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
    if !super::constant_time_eq(pending.state.as_bytes(), state.as_bytes()) {
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
    let http = http_client()?;
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
