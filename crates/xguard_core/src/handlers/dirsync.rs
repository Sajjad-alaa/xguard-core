//! Directory sync with the external OpenID provider: connection test, dry run, sync now and
//! status (admin only, audited).

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    dirsync::{
        self, DirSyncError, SyncConfig,
        sync::{LastRun, SyncOptions},
    },
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    sso::provider::{ProviderConfig, ProviderError, ProviderInput},
};

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DirectorySyncRequest {
    /// Allow a run that disables or deletes many accounts at once.
    #[serde(default)]
    pub confirm_revocations: bool,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DirectorySyncStatus {
    pub enabled: bool,
    /// The last periodic or manual run since XGuard started.
    pub last_run: Option<LastRun>,
}

fn refused(err: DirSyncError) -> ApiResult {
    match err {
        DirSyncError::Database(err) => Err(err.into()),
        err @ DirSyncError::UserManagement(_) => {
            error!("Directory sync failed: {err}");
            Err(WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))
        }
        err => Ok(ApiResponse::new(
            json!({ "msg": err.to_string() }),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// The settings in `input` (unsaved), with stored secrets where none are given. Stored
/// directory identities apply only when the issuer and provider kind are unchanged.
async fn unsaved_config(
    appstate: &AppState,
    input: ProviderInput,
) -> Result<Result<SyncConfig, DirSyncError>, WebError> {
    let stored = ProviderConfig::current(&appstate.pool).await?;
    let mut config = match input.into_config(stored.as_ref()) {
        Ok(config) => config,
        Err(ProviderError::Database(err)) => return Err(err.into()),
        Err(err) => return Ok(Err(err.into())),
    };
    let same_directory = stored.as_ref().is_some_and(|stored| {
        stored
            .provider
            .issuer
            .eq_ignore_ascii_case(&config.provider.issuer)
            && stored.provider.kind == config.provider.kind
    });
    if !same_directory {
        config.provider.id = 0;
    }
    Ok(SyncConfig::from_provider(&config))
}

/// Test directory sync settings
///
/// Signs in to the directory with the given provider settings (stored secrets are used when
/// none are sent) and lists its users and groups. Nothing is saved or changed.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/openid/provider/sync/test",
    tag = "settings",
    request_body = ProviderInput,
    responses(
        (status = 200, description = "Connected; how many users and groups were found.", body = dirsync::ConnectionTest),
        (status = 400, description = "The settings are incomplete or the directory refused them.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn test_directory_sync(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<ProviderInput>,
) -> ApiResult {
    let config = match unsaved_config(&appstate, input).await? {
        Ok(config) => config,
        Err(err) => return refused(err),
    };
    let result = dirsync::test_connection(&config).await;
    info!(
        "User {} tested the directory sync with {}: {}",
        session.user.username,
        config.provider_name,
        match &result {
            Ok(found) => format!("{} users, {} groups", found.users, found.groups),
            Err(err) => err.to_string(),
        }
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DirectorySyncTested {
            provider: config.provider_name.clone(),
            success: result.is_ok(),
        }),
    })?;
    match result {
        Ok(found) => Ok(ApiResponse::json(found, StatusCode::OK)),
        Err(err) => refused(err),
    }
}

/// Preview a directory sync with the given settings
///
/// Plans a sync with the provider settings in the request (stored secrets are used when none
/// are sent) without saving them or changing anything.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/openid/provider/sync/dry_run",
    tag = "settings",
    request_body = ProviderInput,
    responses(
        (status = 200, description = "The changes a sync with these settings would make.", body = Object),
        (status = 400, description = "The settings are incomplete or the directory refused them.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn preview_directory_sync(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<ProviderInput>,
) -> ApiResult {
    let config = match unsaved_config(&appstate, input).await? {
        Ok(config) => config,
        Err(err) => return refused(err),
    };
    info!(
        "User {} previewed a directory sync with {}",
        session.user.username, config.provider_name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DirectorySyncStarted {
            provider: config.provider_name.clone(),
            dry_run: true,
        }),
    })?;
    let options = SyncOptions {
        dry_run: true,
        confirm_revocations: false,
    };
    match dirsync::sync::run(
        &appstate.pool,
        &config,
        options,
        &appstate.dirsync_tx,
        &appstate.gateway_tx,
    )
    .await
    {
        Ok(report) => Ok(ApiResponse::json(report, StatusCode::OK)),
        Err(err) => refused(err),
    }
}

/// Sync with the directory now
///
/// Runs a sync with the saved settings and returns the plan with any errors. A run that would
/// disable or delete many accounts is refused unless `confirm_revocations` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/openid/provider/sync",
    tag = "settings",
    request_body = DirectorySyncRequest,
    responses(
        (status = 200, description = "The plan, whether it was applied, and errors.", body = Object),
        (status = 400, description = "The sync is off or misconfigured, or the run was refused.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn sync_directory_now(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(request): Json<DirectorySyncRequest>,
) -> ApiResult {
    let Some(stored) = ProviderConfig::current(&appstate.pool).await? else {
        return Err(ProviderError::NotFound.into());
    };
    if !stored.provider.directory_sync.directory_sync_enabled {
        return refused(DirSyncError::Disabled);
    }
    let config = match SyncConfig::from_provider(&stored) {
        Ok(config) => config,
        Err(err) => return refused(err),
    };
    info!(
        "User {} started a directory sync with {}{}",
        session.user.username,
        config.provider_name,
        if request.confirm_revocations {
            " (revocations confirmed)"
        } else {
            ""
        }
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DirectorySyncStarted {
            provider: config.provider_name.clone(),
            dry_run: false,
        }),
    })?;
    let options = SyncOptions {
        dry_run: false,
        confirm_revocations: request.confirm_revocations,
    };
    match dirsync::sync::run(
        &appstate.pool,
        &config,
        options,
        &appstate.dirsync_tx,
        &appstate.gateway_tx,
    )
    .await
    {
        Ok(report) => Ok(ApiResponse::json(report, StatusCode::OK)),
        Err(err) => refused(err),
    }
}

/// Directory sync status
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/openid/provider/sync/status",
    tag = "settings",
    responses(
        (status = 200, description = "Whether the sync is on, and how the last run went.", body = DirectorySyncStatus),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn directory_sync_status(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let enabled = ProviderConfig::current(&appstate.pool)
        .await?
        .is_some_and(|config| config.provider.directory_sync.directory_sync_enabled);
    Ok(ApiResponse::json(
        DirectorySyncStatus {
            enabled,
            last_run: dirsync::sync::last_run(),
        },
        StatusCode::OK,
    ))
}
