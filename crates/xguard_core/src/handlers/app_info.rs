use axum::{extract::State, http::StatusCode};
use xguard_common::{
    REPORTED_VERSION,
    db::models::{Settings, WireguardNetwork},
};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{appstate::AppState, auth::SessionInfo};

#[derive(Serialize)]
struct LdapInfo {
    /// Whether that integration is enabled (at least one way synchronization)
    enabled: bool,
    /// Whether AD is used
    ad: bool,
}

/// Additional information about core state.
#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    network_present: bool,
    smtp_enabled: bool,
    ldap_info: LdapInfo,
    external_openid_enabled: bool,
}

/// Get information about this xguard instance
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/info",
    tag = "system",
    responses(
        (status = 200, description = "Instance information: enabled modules, version, license state.", body = Object, example = json!({
            "version": "2.1.0",
            "network_present": true,
            "smtp_enabled": true,
            "ldap_info": {"enabled": false, "ad": false},
            "external_openid_enabled": false
        })),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 500, description = "Unable to get instance information.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn get_app_info(State(appstate): State<AppState>, _session: SessionInfo) -> ApiResult {
    let networks = WireguardNetwork::all(&appstate.pool).await?;

    let settings = Settings::get_current_settings();
    let smtp_enabled = settings.smtp_configured();

    let res = AppInfo {
        network_present: !networks.is_empty(),
        smtp_enabled,
        version: REPORTED_VERSION.into(),
        // LDAP and external OpenID providers are not part of XGuard.
        ldap_info: LdapInfo {
            enabled: false,
            ad: false,
        },
        external_openid_enabled: false,
    };

    Ok(ApiResponse::json(res, StatusCode::OK))
}
