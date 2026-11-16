//! API tokens (admin only).
//!
//! - Admins create tokens for their own account only, from a signed-in session. A token
//!   cannot create more tokens, so a leaked token cannot entrench itself.
//! - Admins can list, rename and revoke anyone's tokens, so they can clean up after others.
//! - Every change goes to the activity log.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use xguard_common::db::{
    Id,
    models::{
        ApiToken, SessionState, User,
        api_token::{ApiTokenError, NewApiToken},
    },
};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreatedApiToken {
    /// The token itself. It is shown only in this response.
    pub token: String,
    pub api_token: ApiToken,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenameApiToken {
    pub name: String,
}

async fn find_user(appstate: &AppState, username: &str) -> Result<User<Id>, WebError> {
    User::find_by_username(&appstate.pool, username)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("user {username} not found")))
}

/// List a user's API tokens
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/user/{username}/api_token",
    tag = "api token",
    params(("username" = String, Path, description = "Token owner")),
    responses(
        (status = 200, description = "The user's tokens, newest first. Token values are never returned.", body = [ApiToken]),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
        (status = 404, description = "No such user.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn list_api_tokens(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult {
    let user = find_user(&appstate, &username).await?;
    let tokens = ApiToken::find_by_user(&appstate.pool, user.id).await?;
    Ok(ApiResponse::json(tokens, StatusCode::OK))
}

/// Create an API token
///
/// Only for your own account, from a signed-in session (not with another token). The token
/// value is in the response and cannot be retrieved again.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/user/{username}/api_token",
    tag = "api token",
    params(("username" = String, Path, description = "Your own username")),
    request_body = NewApiToken,
    responses(
        (status = 201, description = "Token created.", body = CreatedApiToken),
        (status = 400, description = "Invalid name or lifetime, or too many tokens.", body = ApiErrorResponse),
        (status = 403, description = "Not your account, or the request used an API token.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn create_api_token(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(username): Path<String>,
    Json(input): Json<NewApiToken>,
) -> ApiResult {
    if session.session.state == SessionState::ApiTokenVerified {
        return Err(WebError::Forbidden(
            "API tokens cannot create API tokens; sign in to create one",
        ));
    }
    if session.user.username != username {
        return Err(WebError::Forbidden(
            "API tokens can only be created for your own account",
        ));
    }
    let mut transaction = appstate.pool.begin().await?;
    let (api_token, token) = ApiToken::create(&mut transaction, session.user.id, &input).await?;
    transaction.commit().await?;
    info!(
        "User {username} created API token {} ({})",
        api_token.name, api_token.id
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ApiTokenAdded {
            owner: session.user.clone(),
            token: api_token.clone(),
        }),
    })?;
    Ok(ApiResponse::json(
        CreatedApiToken { token, api_token },
        StatusCode::CREATED,
    ))
}

/// Rename an API token
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/user/{username}/api_token/{token_id}/rename",
    tag = "api token",
    params(
        ("username" = String, Path, description = "Token owner"),
        ("token_id" = Id, Path, description = "Token ID"),
    ),
    request_body = RenameApiToken,
    responses(
        (status = 200, description = "Token renamed.", body = ApiToken),
        (status = 400, description = "Invalid name.", body = ApiErrorResponse),
        (status = 404, description = "No such user or token.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn rename_api_token(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path((username, token_id)): Path<(String, Id)>,
    Json(input): Json<RenameApiToken>,
) -> ApiResult {
    let owner = find_user(&appstate, &username).await?;
    let before = ApiToken::find_for_user(&appstate.pool, token_id, owner.id)
        .await?
        .ok_or(ApiTokenError::NotFound)?;
    let token = ApiToken::rename(&appstate.pool, token_id, owner.id, &input.name).await?;
    info!(
        "User {} renamed API token {token_id} of {username} from {} to {}",
        session.user.username, before.name, token.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ApiTokenRenamed {
            owner,
            old_name: before.name,
            new_name: token.name.clone(),
            token: token.clone(),
        }),
    })?;
    Ok(ApiResponse::json(token, StatusCode::OK))
}

/// Revoke an API token
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/user/{username}/api_token/{token_id}",
    tag = "api token",
    params(
        ("username" = String, Path, description = "Token owner"),
        ("token_id" = Id, Path, description = "Token ID"),
    ),
    responses(
        (status = 200, description = "Token revoked; it stops working at once."),
        (status = 404, description = "No such user or token.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn delete_api_token(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path((username, token_id)): Path<(String, Id)>,
) -> ApiResult {
    let owner = find_user(&appstate, &username).await?;
    let token = ApiToken::delete(&appstate.pool, token_id, owner.id)
        .await?
        .ok_or(ApiTokenError::NotFound)?;
    info!(
        "User {} revoked API token {} ({token_id}) of {username}",
        session.user.username, token.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ApiTokenRemoved { owner, token }),
    })?;
    Ok(ApiResponse::default())
}
