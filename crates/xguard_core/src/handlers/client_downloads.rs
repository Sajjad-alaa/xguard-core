//! Client download links (Settings -> Client downloads).

use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use xguard_common::db::models::{
    Settings,
    client_downloads::{
        CLIENT_ASSET_NAMES, ClientDownloadSettings, DEFAULT_CLIENT_DOWNLOAD_BASE_URL,
        DEFAULT_CLIENT_RELEASES_URL,
    },
};

use super::{ApiResponse, ApiResult, settings::broadcast_public_settings};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

/// One update at a time in this process, so the cache ends up with the last committed value.
static UPDATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientDownloadDefaults {
    pub base_url: &'static str,
    pub releases_url: &'static str,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientDownloadsResponse {
    #[serde(flatten)]
    pub settings: ClientDownloadSettings,
    /// Installer file names appended to `base_url`.
    pub asset_names: [&'static str; 6],
    /// Built-in values, for "restore defaults".
    pub defaults: ClientDownloadDefaults,
}

impl From<ClientDownloadSettings> for ClientDownloadsResponse {
    fn from(settings: ClientDownloadSettings) -> Self {
        Self {
            settings,
            asset_names: CLIENT_ASSET_NAMES,
            defaults: ClientDownloadDefaults {
                base_url: DEFAULT_CLIENT_DOWNLOAD_BASE_URL,
                releases_url: DEFAULT_CLIENT_RELEASES_URL,
            },
        }
    }
}

/// Get the client download links. Every signed-in user may read them: the add-device dialog
/// shows them.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/client_downloads",
    tag = "settings",
    responses(
        (status = 200, description = "Client download links.", body = ClientDownloadsResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_client_downloads(
    _session: SessionInfo,
    State(appstate): State<AppState>,
) -> ApiResult {
    let settings = ClientDownloadSettings::current(&appstate.pool).await?;
    Ok(ApiResponse::json(
        ClientDownloadsResponse::from(settings),
        StatusCode::OK,
    ))
}

/// Replace the client download links. URLs must use https; plain http needs `allow_http`.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/client_downloads",
    tag = "settings",
    request_body = ClientDownloadSettings,
    responses(
        (status = 200, description = "Saved client download links.", body = ClientDownloadsResponse),
        (status = 400, description = "Invalid URL.", body = ApiErrorResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn put_client_downloads(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<ClientDownloadSettings>,
) -> ApiResult {
    let after = input
        .canonicalize()
        .map_err(|err| WebError::BadRequest(err.to_string()))?;
    let _guard = UPDATE_LOCK.lock().await;
    let mut transaction = appstate.pool.begin().await?;
    // Serialize concurrent updates from other Core processes as well.
    sqlx::query("LOCK TABLE client_download_settings IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await?;
    let before = ClientDownloadSettings::load(&mut *transaction).await?;
    if after == before {
        transaction.rollback().await?;
        return Ok(ApiResponse::json(
            ClientDownloadsResponse::from(after),
            StatusCode::OK,
        ));
    }
    after.save(&mut *transaction).await?;
    transaction.commit().await?;
    after.clone().set_cached();
    if after.uses_http() {
        warn!(
            "User {} set client download links that use plain HTTP; installers can be replaced \
            in transit, use HTTPS where possible",
            session.user.username
        );
    }
    info!(
        "User {} updated the client download links (base URL {})",
        session.user.username, after.base_url
    );
    broadcast_public_settings(
        &appstate.pool,
        &Settings::get_current_settings(),
        &appstate.proxy_control_tx,
    )
    .await;
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ClientDownloadsUpdated {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(
        ClientDownloadsResponse::from(after),
        StatusCode::OK,
    ))
}
