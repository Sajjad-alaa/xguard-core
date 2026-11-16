//! LDAP and Active Directory: connection test and on-demand sync (admin only).

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use xguard_common::db::models::Settings;

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    directory::{self, DirectoryConfig, DirectoryError, SyncOptions},
};

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncRequest {
    /// Only report what would change.
    #[serde(default)]
    pub dry_run: bool,
    /// Allow a run that deletes many accounts at once.
    #[serde(default)]
    pub confirm_deletions: bool,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectionTest {
    pub users: usize,
    pub groups: usize,
}

/// Test directory settings
///
/// Connects with the given settings (the stored bind password is used when none is sent),
/// binds and reads users and groups. Nothing is saved or changed.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/ldap/test",
    tag = "settings",
    request_body = Settings,
    responses(
        (status = 200, description = "Connected; how many users and groups were found.", body = ConnectionTest),
        (status = 400, description = "The settings are incomplete or the directory refused them.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn test_directory(
    _admin: AdminRole,
    session: SessionInfo,
    Json(mut data): Json<Settings>,
) -> ApiResult {
    let stored = Settings::get_current_settings();
    data.ldap_bind_password = data.ldap_bind_password.or(stored.ldap_bind_password);
    match directory::test_connection(&data).await {
        Ok((users, groups)) => {
            info!(
                "User {} tested the directory connection: {users} users, {groups} groups",
                session.user.username
            );
            Ok(ApiResponse::json(
                ConnectionTest { users, groups },
                StatusCode::OK,
            ))
        }
        Err(err) => {
            warn!("Directory connection test failed: {err}");
            Ok(ApiResponse::new(
                json!({ "msg": err.to_string() }),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}

/// Preview a sync with the given settings
///
/// Plans a sync with the settings in the request (the stored bind password is used when none is
/// sent) without saving them or changing anything, so an admin can check them first.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/ldap/dry_run",
    tag = "settings",
    request_body = Settings,
    responses(
        (status = 200, description = "The changes a sync with these settings would make.", body = Object),
        (status = 400, description = "The settings are incomplete or the directory refused them.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn preview_directory_sync(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Json(mut data): Json<Settings>,
) -> ApiResult {
    let stored = Settings::get_current_settings();
    data.ldap_bind_password = data.ldap_bind_password.or(stored.ldap_bind_password);
    // A preview always plans a two-way sync, so it shows both directions.
    data.ldap_enabled = true;
    data.ldap_sync_enabled = true;
    let result = async {
        let config = DirectoryConfig::from_settings(&data)?;
        directory::sync::run(
            &appstate.pool,
            config,
            SyncOptions {
                dry_run: true,
                confirm_deletions: false,
            },
            &appstate.ldap_tx,
            &appstate.gateway_tx,
        )
        .await
    }
    .await;
    match result {
        Ok(report) => Ok(ApiResponse::json(report, StatusCode::OK)),
        Err(err @ DirectoryError::Database(_)) => Err(err.into()),
        Err(err) => Ok(ApiResponse::new(
            json!({ "msg": err.to_string() }),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Sync with the directory now
///
/// With `dry_run`, returns the planned changes without making them. Otherwise applies them and
/// returns the plan with any errors. A run that would delete many accounts is refused unless
/// `confirm_deletions` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/ldap/sync",
    tag = "settings",
    request_body = SyncRequest,
    responses(
        (status = 200, description = "The plan, whether it was applied, and errors.", body = Object),
        (status = 400, description = "The integration is off or misconfigured, or the run was refused.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn sync_directory(
    _admin: AdminRole,
    session: SessionInfo,
    State(appstate): State<AppState>,
    Json(request): Json<SyncRequest>,
) -> ApiResult {
    let config = match directory::enabled_config() {
        Ok(config) => config,
        Err(err) => {
            return Ok(ApiResponse::new(
                json!({ "msg": err.to_string() }),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    info!(
        "User {} started a directory sync{}",
        session.user.username,
        if request.dry_run { " (dry run)" } else { "" }
    );
    let result = directory::sync::run(
        &appstate.pool,
        config,
        SyncOptions {
            dry_run: request.dry_run,
            confirm_deletions: request.confirm_deletions,
        },
        &appstate.ldap_tx,
        &appstate.gateway_tx,
    )
    .await;
    match result {
        Ok(report) => Ok(ApiResponse::json(report, StatusCode::OK)),
        Err(err @ (DirectoryError::Database(_) | DirectoryError::UserManagement(_))) => {
            Err(err.into())
        }
        Err(err) => Ok(ApiResponse::new(
            json!({ "msg": err.to_string() }),
            StatusCode::BAD_REQUEST,
        )),
    }
}
