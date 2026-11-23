//! Registered device limits and simultaneous MFA VPN connection limits API.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
#[cfg(feature = "openapi")]
use xguard_common::db::models::device_limit::UserDeviceLimitInfo;
use xguard_common::db::{
    Id,
    models::{
        User,
        device_limit::{
            DeviceLimitOverride, DeviceLimitSettings, GroupDeviceLimit, get_group_limit,
            get_user_limit_info, get_user_override, list_group_limits, set_group_limit,
            set_user_override,
        },
        group::Group,
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

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceLimitsOverview {
    #[serde(flatten)]
    pub settings: DeviceLimitSettings,
    pub group_overrides: Vec<GroupDeviceLimit>,
}

/// Get global device and simultaneous connection limits plus group overrides.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device_limits",
    tag = "settings",
    responses(
        (status = 200, description = "Global device limits and group overrides.", body = DeviceLimitsOverview),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_device_limits(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let settings = DeviceLimitSettings::load(&appstate.pool).await?;
    let group_overrides = list_group_limits(&appstate.pool).await?;
    Ok(ApiResponse::json(
        DeviceLimitsOverview {
            settings,
            group_overrides,
        },
        StatusCode::OK,
    ))
}

/// Update global default device and simultaneous MFA connection limits (`0` = unlimited).
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/api/v1/device_limits",
    tag = "settings",
    request_body = DeviceLimitSettings,
    responses(
        (status = 200, description = "Updated global device limits.", body = DeviceLimitSettings),
        (status = 400, description = "Invalid limit value.", body = ApiErrorResponse),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn patch_device_limits(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<DeviceLimitSettings>,
) -> ApiResult {
    let mut tx = appstate.pool.begin().await?;
    let before = DeviceLimitSettings::load(&mut *tx).await?;
    let after = input.save(&mut tx).await?;
    tx.commit().await?;
    if before != after {
        info!(
            "User {} updated global device limits: {before:?} -> {after:?}",
            session.user.username
        );
        appstate.emit_event(ApiEvent {
            context,
            event: Box::new(ApiEventType::DeviceLimitsUpdated { before, after }),
        })?;
    }
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Get per-group device and connection limit overrides.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device_limits/group/{id}",
    tag = "settings",
    params(("id" = Id, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group override.", body = DeviceLimitOverride),
        (status = 404, description = "Group not found.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_group_device_limit(
    _admin: AdminRole,
    Path(group_id): Path<Id>,
    State(appstate): State<AppState>,
) -> ApiResult {
    Group::find_by_id(&appstate.pool, group_id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("group {group_id} not found")))?;
    let limit = get_group_limit(&appstate.pool, group_id).await?;
    Ok(ApiResponse::json(limit, StatusCode::OK))
}

/// Set or clear per-group device and connection limit overrides.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/device_limits/group/{id}",
    tag = "settings",
    params(("id" = Id, Path, description = "Group ID")),
    request_body = DeviceLimitOverride,
    responses(
        (status = 200, description = "Updated group override.", body = DeviceLimitOverride),
        (status = 400, description = "Invalid limit value.", body = ApiErrorResponse),
        (status = 404, description = "Group not found.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn put_group_device_limit(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    Path(group_id): Path<Id>,
    State(appstate): State<AppState>,
    Json(input): Json<DeviceLimitOverride>,
) -> ApiResult {
    let group = Group::find_by_id(&appstate.pool, group_id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("group {group_id} not found")))?;
    let mut tx = appstate.pool.begin().await?;
    let before = get_group_limit(&mut *tx, group_id).await?;
    let after = set_group_limit(&mut tx, group_id, input).await?;
    tx.commit().await?;
    if before != after {
        info!(
            "User {} updated device limits for group '{}': {before:?} -> {after:?}",
            session.user.username, group.name
        );
        appstate.emit_event(ApiEvent {
            context,
            event: Box::new(ApiEventType::GroupDeviceLimitUpdated {
                group_id,
                group_name: group.name,
                before,
                after,
            }),
        })?;
    }
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Get a user's current registered device count, effective limits, and per-user overrides.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device_limits/user/{id}",
    tag = "settings",
    params(("id" = Id, Path, description = "User ID")),
    responses(
        (status = 200, description = "User device limit info.", body = UserDeviceLimitInfo),
        (status = 403, description = "Forbidden.", body = ApiErrorResponse),
        (status = 404, description = "User not found.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_user_device_limit(
    session: SessionInfo,
    Path(user_id): Path<Id>,
    State(appstate): State<AppState>,
) -> ApiResult {
    if !session.is_admin && session.user.id != user_id {
        return Err(WebError::Forbidden("requires privileged access"));
    }
    User::find_by_id(&appstate.pool, user_id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("user {user_id} not found")))?;
    let mut conn = appstate.pool.acquire().await?;
    let info = get_user_limit_info(&mut conn, user_id).await?;
    Ok(ApiResponse::json(info, StatusCode::OK))
}

/// Set or clear per-user device and connection limit overrides (admin only).
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/device_limits/user/{id}",
    tag = "settings",
    params(("id" = Id, Path, description = "User ID")),
    request_body = DeviceLimitOverride,
    responses(
        (status = 200, description = "Updated user device limit info.", body = UserDeviceLimitInfo),
        (status = 400, description = "Invalid limit value.", body = ApiErrorResponse),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
        (status = 404, description = "User not found.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn put_user_device_limit(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    Path(user_id): Path<Id>,
    State(appstate): State<AppState>,
    Json(input): Json<DeviceLimitOverride>,
) -> ApiResult {
    let user = User::find_by_id(&appstate.pool, user_id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("user {user_id} not found")))?;
    let mut tx = appstate.pool.begin().await?;
    let before = get_user_override(&mut *tx, user_id).await?;
    let after = set_user_override(&mut tx, user_id, input).await?;
    let info = get_user_limit_info(&mut tx, user_id).await?;
    tx.commit().await?;
    if before != after {
        info!(
            "User {} updated device limits for user '{}': {before:?} -> {after:?}",
            session.user.username, user.username
        );
        appstate.emit_event(ApiEvent {
            context,
            event: Box::new(ApiEventType::UserDeviceLimitUpdated {
                user_id,
                username: user.username,
                before,
                after,
            }),
        })?;
    }
    Ok(ApiResponse::json(info, StatusCode::OK))
}
