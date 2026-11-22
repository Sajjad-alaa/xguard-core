use axum::{
    Extension,
    extract::{Json, Path, State},
    http::StatusCode,
};
use sqlx::PgPool;
use struct_patch::Patch;
use tokio::sync::mpsc;
use xguard_common::{
    db::{
        Id,
        models::{
            ClientSettings, Settings, SettingsEssentials,
            settings::{SettingsPatch, update_current_settings},
        },
    },
    types::proxy::ProxyControlMessage,
};
use xguard_proto::proxy::PublicSettings;

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

static DEFAULT_NAV_LOGO_URL: &str = "/svg/xguard-nav-logo.svg";
static DEFAULT_MAIN_LOGO_URL: &str = "/svg/logo-xguard-white.svg";

/// Settings the Edge (proxy) shows on its public pages. Password reset needs email delivery, so
/// it is offered only when the admin allows it and SMTP is configured.
#[must_use]
pub fn edge_public_settings(settings: &Settings, client: &ClientSettings) -> PublicSettings {
    PublicSettings {
        display_password_reset: client.display_password_reset && settings.smtp_configured(),
        display_download_step: client.display_download_step,
        public_url: settings.configured_public_proxy_url(),
        directory_enrollment: settings.directory_enrollment_enabled(),
    }
}

/// Wrap `PublicSettings` in the control message the proxy manager fans out to every connected
/// proxy. Build the payload with [`edge_public_settings`].
#[must_use]
pub(crate) fn public_settings_message(public_settings: PublicSettings) -> ProxyControlMessage {
    ProxyControlMessage::BroadcastPublicSettings {
        display_password_reset: public_settings.display_password_reset,
        display_download_step: public_settings.display_download_step,
        public_url: public_settings.public_url,
        directory_enrollment: public_settings.directory_enrollment,
    }
}

/// Push the current `PublicSettings` to every connected proxy. Best effort: a send failure is
/// logged rather than propagated, since proxies also receive the current values when they next
/// connect.
pub(crate) async fn broadcast_public_settings(
    pool: &PgPool,
    settings: &Settings,
    proxy_control_tx: &mpsc::Sender<ProxyControlMessage>,
) {
    let client = match ClientSettings::current(pool).await {
        Ok(client) => client,
        Err(err) => {
            error!("Failed to load client settings for the Edge public settings: {err}");
            return;
        }
    };
    let message = public_settings_message(edge_public_settings(settings, &client));
    if let Err(err) = proxy_control_tx.send(message).await {
        error!("Failed to broadcast PublicSettings after public proxy URL change: {err:?}");
    }
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SettingsResponse {
    #[serde(flatten)]
    settings: Settings,
    ldap_bind_password_set: bool,
    smtp_password_set: bool,
    smtp_oauth_client_secret_set: bool,
    smtp_oauth_refresh_token_set: bool,
}

impl From<Settings> for SettingsResponse {
    fn from(value: Settings) -> Self {
        Self {
            ldap_bind_password_set: value.ldap_bind_password.is_some(),
            smtp_password_set: value.smtp.password.is_some(),
            smtp_oauth_client_secret_set: value.smtp.oauth_client_secret.is_some(),
            smtp_oauth_refresh_token_set: value.smtp.oauth_refresh_token.is_some(),
            settings: value,
        }
    }
}

/// Get instance settings
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/settings",
    tag = "settings",
    responses(
        (status = 200, description = "Instance settings.", body = SettingsResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to get settings.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn get_settings(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    debug!("Retrieving settings");
    if let Some(mut settings) = Settings::get(&appstate.pool).await? {
        if settings.nav_logo_url.is_empty() {
            settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
        }
        if settings.main_logo_url.is_empty() {
            settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
        }
        return Ok(ApiResponse::json(
            SettingsResponse::from(settings),
            StatusCode::OK,
        ));
    }
    debug!("Retrieved settings");
    Ok(ApiResponse::default())
}

/// Replace instance settings
///
/// The whole settings object has to be sent. Use `PATCH` to update selected fields only.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/settings",
    tag = "settings",
    request_body = Settings,
    responses(
        (status = 200, description = "Settings updated."),
        (status = 400, description = "Invalid settings.", body = ApiErrorResponse, example = json!({"msg": "Invalid settings"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to update settings.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn update_settings(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(mut data): Json<Settings>,
) -> ApiResult {
    debug!("User {} updating settings", session.user.username);

    // fetch current settings for event
    let before = Settings::get_current_settings();
    data.uuid = before.uuid;
    data.default_admin_id = before.default_admin_id;
    data.ldap_sync_status = before.ldap_sync_status;
    data.invalidate_ldap_sync_status(&before);
    data.set_secret_key(before.secret_key().map(str::to_owned));
    data.openid_signing_key_der = before.openid_signing_key_der.clone();
    data.smtp.password = data.smtp.password.or(before.smtp.password.clone());
    data.smtp.oauth_client_secret = data
        .smtp
        .oauth_client_secret
        .or(before.smtp.oauth_client_secret.clone());
    data.smtp.oauth_refresh_token = before.smtp.oauth_refresh_token.clone();
    crate::mail::xoauth2::protect_settings(&before.smtp, &mut data.smtp);
    data.ldap_bind_password = data
        .ldap_bind_password
        .or(before.ldap_bind_password.clone());
    data.validate()?;
    // clone for event
    let after = data.clone();

    update_current_settings(&appstate.pool, data).await?;

    if before.edge_public_settings_changed(&after) {
        broadcast_public_settings(&appstate.pool, &after, &appstate.proxy_control_tx).await;
    }

    info!("User {} updated settings", session.user.username);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::SettingsUpdated { before, after }),
    })?;

    Ok(ApiResponse::default())
}

/// Get settings required to render the web UI
///
/// Public endpoint. Returns only non-sensitive settings.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/settings_essentials",
    tag = "settings",
    responses(
        (status = 200, description = "Essential settings.", body = Object, example = json!({
            "instance_name": "xguard",
            "main_logo_url": "/svg/logo-xguard-white.svg",
            "nav_logo_url": "/svg/xguard-nav-logo.svg",
            "wireguard_enabled": true,
            "webhooks_enabled": true,
            "worker_enabled": false,
            "openid_enabled": true
        })),
        (status = 500, description = "Unable to get essential settings.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
))]
pub async fn get_settings_essentials(Extension(pool): Extension<PgPool>) -> ApiResult {
    debug!("Retrieving essential settings");
    let mut settings = SettingsEssentials::get_settings_essentials(&pool).await?;
    if settings.nav_logo_url.is_empty() {
        settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
    }
    if settings.main_logo_url.is_empty() {
        settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
    }

    info!("Retrieved essential settings");

    Ok(ApiResponse::json(settings, StatusCode::OK))
}

/// Restore default branding settings
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/settings/{id}",
    tag = "settings",
    params(
        ("id" = i64, Path, description = "Not used."),
    ),
    responses(
        (status = 200, description = "Instance settings, with the branding fields restored to defaults.", body = SettingsResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to restore default branding settings.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn set_default_branding(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(_id): Path<Id>, // TODO: check with front-end and remove.
    session: SessionInfo,
    context: ApiRequestContext,
) -> ApiResult {
    debug!(
        "User {} restoring default branding settings",
        session.user.username
    );
    let settings = Settings::get(&appstate.pool).await?;
    match settings {
        Some(mut settings) => {
            settings.instance_name = "XGuard".into();
            settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
            settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
            update_current_settings(&appstate.pool, settings.clone()).await?;
            info!(
                "User {} restored default branding settings",
                session.user.username
            );
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::SettingsDefaultBrandingRestored),
            })?;
            Ok(ApiResponse::json(
                SettingsResponse::from(settings),
                StatusCode::OK,
            ))
        }
        None => Err(WebError::DbError("Cannot restore settings".into())),
    }
}

/// Update selected instance settings
///
/// Only the fields present in the request body are modified. Sending `null` clears a field.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/api/v1/settings",
    tag = "settings",
    request_body = Object,
    responses(
        (status = 200, description = "Settings updated."),
        (status = 400, description = "Invalid settings.", body = ApiErrorResponse, example = json!({"msg": "Invalid settings"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to update settings.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn patch_settings(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
    Json(mut data): Json<SettingsPatch>,
) -> ApiResult {
    debug!("Admin {} is patching settings", session.user.username);
    let mut settings = Settings::get_current_settings();
    // Keep the pre-patch settings for validation and event reporting.
    let before = settings.clone();
    // Refresh tokens only come from the OAuth callback; ignore caller-supplied non-null tokens.
    if matches!(data.smtp.oauth_refresh_token, Some(Some(_))) {
        data.smtp.oauth_refresh_token = None;
    }
    settings.apply(data);
    crate::mail::xoauth2::protect_settings(&before.smtp, &mut settings.smtp);
    settings.invalidate_ldap_sync_status(&before);
    settings.validate_against(&before)?;

    // clone for event
    let after = settings.clone();
    update_current_settings(&appstate.pool, settings).await?;

    if before.edge_public_settings_changed(&after) {
        broadcast_public_settings(&appstate.pool, &after, &appstate.proxy_control_tx).await;
    }

    info!("Admin {} patched settings", session.user.username);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::SettingsUpdatedPartial { before, after }),
    })?;

    Ok(ApiResponse::default())
}
