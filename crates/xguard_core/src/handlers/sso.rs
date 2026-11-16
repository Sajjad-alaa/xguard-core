//! Sign-in with an external OpenID Connect provider, and its settings.

use axum::{Json, extract::State, http::StatusCode};
use axum_extra::{
    TypedHeader,
    extract::{
        CookieJar, PrivateCookieJar,
        cookie::{Cookie, SameSite},
    },
    headers::UserAgent,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;
use xguard_common::{config::server_config, db::models::Settings};

use super::{
    ApiResponse, ApiResult, AuthResponse, ClientIpAddr,
    auth::{create_session, session_cookie},
};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    sso::{
        self, LinkError,
        flow::{self, FlowError, PendingLogin},
        provider::{OpenIdProvider, ProviderConfig, ProviderError, ProviderInput, ProviderKind},
    },
};

/// Holds the state, nonce and PKCE verifier of a sign-in in progress (encrypted).
const PENDING_COOKIE: &str = "xguard_openid_login";
const PENDING_COOKIE_PATH: &str = "/api/v1/openid";
const PENDING_LIFETIME: Duration = Duration::minutes(10);

impl From<ProviderError> for WebError {
    fn from(err: ProviderError) -> Self {
        match err {
            ProviderError::Invalid(_) => Self::BadRequest(err.to_string()),
            ProviderError::NotFound => Self::ObjectNotFound(err.to_string()),
            ProviderError::Database(err) => err.into(),
        }
    }
}

fn redirect_url() -> Result<String, WebError> {
    let url = Settings::url().map_err(|err| {
        error!("The XGuard URL is invalid: {err}");
        WebError::BadRequest("The XGuard URL setting is invalid".into())
    })?;
    Ok(format!(
        "{}/auth/callback",
        url.as_str().trim_end_matches('/')
    ))
}

fn secure_cookies() -> Result<bool, WebError> {
    Ok(server_config().cookie_insecure.map_or(
        Settings::get_current_settings().cookie_secure()?,
        |insecure| !insecure,
    ))
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthInfo {
    /// Where to send the browser.
    pub url: String,
    pub button_display_name: Option<String>,
    pub provider_kind: ProviderKind,
}

/// Start signing in with the external provider
///
/// Public. Returns the provider's authorization URL and sets an encrypted cookie that the
/// callback needs. Answers 404 when no provider is enabled.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/openid/auth_info",
    tag = "auth",
    responses(
        (status = 200, description = "Where to send the browser.", body = AuthInfo),
        (status = 404, description = "No external provider is enabled.", body = ApiErrorResponse),
    )
))]
pub(crate) async fn auth_info(
    State(appstate): State<AppState>,
    private_cookies: PrivateCookieJar,
) -> Result<(PrivateCookieJar, ApiResponse), WebError> {
    let Some(config) = ProviderConfig::enabled(&appstate.pool).await? else {
        return Err(WebError::ObjectNotFound(
            "No external provider is enabled".into(),
        ));
    };
    let (url, pending) = flow::start(&config, &redirect_url()?)
        .await
        .map_err(|err| {
            warn!("Failed to start an OpenID sign-in: {err}");
            WebError::BadRequest(err.to_string())
        })?;
    let value = serde_json::to_string(&pending)
        .map_err(|_| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))?;
    let cookie = Cookie::build((PENDING_COOKIE, value))
        .path(PENDING_COOKIE_PATH)
        .http_only(true)
        .secure(secure_cookies()?)
        .same_site(SameSite::Lax)
        .max_age(PENDING_LIFETIME);
    Ok((
        private_cookies.add(cookie),
        ApiResponse::json(
            AuthInfo {
                url,
                button_display_name: config.provider.display_name,
                provider_kind: config.provider.kind,
            },
            StatusCode::OK,
        ),
    ))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CallbackRequest {
    pub code: String,
    pub state: String,
}

/// Finish signing in with the external provider
///
/// Exchanges the authorization code, verifies the ID token and signs in the linked account.
/// Like `POST /api/v1/auth`, answers 201 with MFA details when the account uses MFA.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/openid/callback",
    tag = "auth",
    request_body = CallbackRequest,
    responses(
        (status = 200, description = "Signed in.", body = AuthResponse),
        (status = 201, description = "A second factor is required."),
        (status = 401, description = "The sign-in could not be completed.", body = ApiErrorResponse),
    )
))]
pub(crate) async fn callback(
    State(appstate): State<AppState>,
    cookies: CookieJar,
    private_cookies: PrivateCookieJar,
    user_agent: TypedHeader<UserAgent>,
    ClientIpAddr(ip_addr): ClientIpAddr,
    Json(request): Json<CallbackRequest>,
) -> Result<(CookieJar, PrivateCookieJar, ApiResponse), WebError> {
    // The pending sign-in can be used once, whatever happens next.
    let pending = private_cookies
        .get(PENDING_COOKIE)
        .and_then(|cookie| serde_json::from_str::<PendingLogin>(cookie.value()).ok());
    let private_cookies =
        private_cookies.remove(Cookie::build(PENDING_COOKIE).path(PENDING_COOKIE_PATH));
    let failed = |message: String| {
        warn!("OpenID sign-in failed: {message}");
        WebError::Authorization(message)
    };
    let Some(pending) = pending else {
        return Err(failed(FlowError::BadState.to_string()));
    };
    let Some(config) = ProviderConfig::enabled(&appstate.pool).await? else {
        return Err(failed("No external provider is enabled".into()));
    };
    let identity = flow::finish(
        &config,
        &redirect_url()?,
        pending,
        &request.code,
        &request.state,
    )
    .await
    .map_err(|err| failed(err.to_string()))?;
    let mut user = match sso::resolve_user(&appstate.pool, &identity).await {
        Ok(user) => user,
        Err(LinkError::Database(err)) => return Err(err.into()),
        Err(err) => return Err(failed(err.to_string())),
    };
    if !user.is_active {
        return Err(failed(format!("The account {} is disabled", user.username)));
    }

    let (session, user_info, mfa_info) =
        create_session(&appstate.pool, ip_addr, user_agent.as_str(), &mut user).await?;
    let cookies = cookies.add(session_cookie(&session.id)?);
    if let Some(mfa_info) = mfa_info {
        return Ok((
            cookies,
            private_cookies,
            ApiResponse::json(mfa_info, StatusCode::CREATED),
        ));
    }
    let Some(user_info) = user_info else {
        return Err(WebError::Http(StatusCode::INTERNAL_SERVER_ERROR));
    };
    info!("User {} signed in through OpenID", user_info.username);
    appstate.emit_event(ApiEvent {
        context: ApiRequestContext::new(
            user_info.id,
            user_info.username.clone(),
            ip_addr,
            user_agent.to_string(),
        ),
        event: Box::new(ApiEventType::UserLogin),
    })?;
    Ok((
        cookies,
        private_cookies,
        ApiResponse::json(
            AuthResponse {
                user: user_info,
                url: None,
            },
            StatusCode::OK,
        ),
    ))
}

/// Get the external OpenID provider
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/openid/provider",
    tag = "settings",
    responses(
        (status = 200, description = "The provider; the client secret is never returned.", body = OpenIdProvider),
        (status = 404, description = "No provider is configured.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_provider(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let config = ProviderConfig::current(&appstate.pool)
        .await?
        .ok_or(ProviderError::NotFound)?;
    Ok(ApiResponse::json(config.provider, StatusCode::OK))
}

/// Set the external OpenID provider
///
/// Replaces the provider. Leave `client_secret` out to keep the stored one. Changing the issuer
/// unlinks all accounts, which link again through their verified email.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/openid/provider",
    tag = "settings",
    request_body = ProviderInput,
    responses(
        (status = 200, description = "Provider saved.", body = OpenIdProvider),
        (status = 400, description = "Invalid settings.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub(crate) async fn set_provider(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<ProviderInput>,
) -> ApiResult {
    let mut transaction = appstate.pool.begin().await?;
    let provider = ProviderConfig::save(&mut transaction, input).await?;
    transaction.commit().await?;
    info!(
        "User {} set the OpenID provider to {}",
        session.user.username, provider.issuer
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::OpenIdProviderModified {
            provider: provider.clone(),
        }),
    })?;
    Ok(ApiResponse::json(provider, StatusCode::OK))
}

/// Remove the external OpenID provider
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/openid/provider",
    tag = "settings",
    responses(
        (status = 200, description = "Provider removed."),
        (status = 404, description = "No provider is configured.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub(crate) async fn delete_provider(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
) -> ApiResult {
    let provider = ProviderConfig::delete(&appstate.pool).await?;
    info!("User {} removed the OpenID provider", session.user.username);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::OpenIdProviderRemoved { provider }),
    })?;
    Ok(ApiResponse::default())
}

/// Check external provider settings
///
/// Fetches the provider's discovery document with the given settings, without saving them.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/openid/provider/test",
    tag = "settings",
    request_body = ProviderInput,
    responses(
        (status = 200, description = "The provider answered with valid metadata."),
        (status = 400, description = "Invalid settings, or the provider could not be reached.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn test_provider(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Json(input): Json<ProviderInput>,
) -> ApiResult {
    let stored = ProviderConfig::current(&appstate.pool)
        .await?
        .map(|config| config.client_secret);
    let (input, client_secret) = input.validate(stored)?;
    let config = ProviderConfig {
        provider: OpenIdProvider {
            id: 0,
            kind: input.kind,
            issuer: input.issuer,
            client_id: input.client_id,
            enabled: input.enabled,
            display_name: input.display_name,
            disable_password_management: input.disable_password_management,
            client_secret_set: true,
        },
        client_secret,
    };
    match flow::check(&config).await {
        Ok(()) => Ok(ApiResponse::default()),
        Err(err) => Ok(ApiResponse::new(
            json!({ "msg": err.to_string() }),
            StatusCode::BAD_REQUEST,
        )),
    }
}
