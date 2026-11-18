//! Client and device settings (instance-wide, with per-group traffic policy overrides).
//!
//! - Reading is open to every signed-in user, because the web UI hides device actions the
//!   settings forbid. Group overrides are only returned to admins.
//! - Changing them needs an admin and is written to the activity log. Requests with unknown
//!   fields, duplicate or unknown groups are rejected before anything is saved.
//! - The settings are cached in memory; the cache is replaced only after the transaction commits.
//! - What the settings enforce lives with the code they guard: device handlers, config downloads,
//!   enrollment through Edge and the instance info sent to clients.

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tokio::sync::Mutex;
use xguard_common::db::models::{
    ClientSettings, ClientTrafficPolicy, Settings,
    client_settings::{ClientSettingsInfo, GroupClientTrafficPolicies, ReplaceGroupPoliciesError},
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

static UPDATE_LOCK: Mutex<()> = Mutex::const_new(());

/// Partial update of the client settings. Omitted fields keep their value;
/// `group_client_traffic_policies`, when present, replaces every group override.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ClientSettingsPatch {
    pub admin_device_management: Option<bool>,
    pub only_client_activation: Option<bool>,
    pub client_traffic_policy: Option<ClientTrafficPolicy>,
    pub disable_tunnels: Option<bool>,
    pub display_download_step: Option<bool>,
    pub display_password_reset: Option<bool>,
    pub group_client_traffic_policies: Option<GroupClientTrafficPolicies>,
}

impl ClientSettingsPatch {
    fn apply(self, settings: &mut ClientSettings) -> Option<GroupClientTrafficPolicies> {
        macro_rules! set {
            ($($field:ident),+) => {$(
                if let Some(value) = self.$field {
                    settings.$field = value;
                }
            )+};
        }
        set!(
            admin_device_management,
            only_client_activation,
            client_traffic_policy,
            disable_tunnels,
            display_download_step,
            display_password_reset
        );
        self.group_client_traffic_policies
    }
}

/// Get client and device settings
///
/// Available to every signed-in user. `group_client_traffic_policies` is empty unless the caller
/// is an admin.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/client_settings",
    tag = "settings",
    responses(
        (status = 200, description = "Client settings.", body = ClientSettingsInfo, example = json!({
            "admin_device_management": false,
            "only_client_activation": false,
            "client_traffic_policy": "none",
            "disable_tunnels": false,
            "display_download_step": true,
            "display_password_reset": true,
            "group_client_traffic_policies": {"none": [], "disable_all_traffic": [2], "force_all_traffic": []}
        })),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn get_client_settings(
    session: SessionInfo,
    State(appstate): State<AppState>,
) -> ApiResult {
    let settings = ClientSettings::current(&appstate.pool).await?;
    let group_client_traffic_policies = if session.is_admin {
        GroupClientTrafficPolicies::load(&appstate.pool).await?
    } else {
        GroupClientTrafficPolicies::default()
    };
    Ok(ApiResponse::json(
        ClientSettingsInfo {
            settings,
            group_client_traffic_policies,
        },
        StatusCode::OK,
    ))
}

/// Update client and device settings
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/api/v1/client_settings",
    tag = "settings",
    request_body = ClientSettingsPatch,
    responses(
        (status = 200, description = "The settings after the update.", body = ClientSettingsInfo),
        (status = 400, description = "Invalid settings.", body = ApiErrorResponse, example = json!({"msg": "group 3 is assigned to more than one client traffic policy"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn patch_client_settings(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(patch): Json<ClientSettingsPatch>,
) -> ApiResult {
    debug!("User {} updating client settings", session.user.username);
    // One update at a time in this process, so the cache ends up with the last committed value.
    let _guard = UPDATE_LOCK.lock().await;
    let mut transaction = appstate.pool.begin().await?;
    // Serialize concurrent updates so neither silently overwrites the other.
    sqlx::query("SELECT id FROM enterprisesettings WHERE id = 1 FOR UPDATE")
        .execute(&mut *transaction)
        .await?;
    let before = ClientSettingsInfo {
        settings: ClientSettings::load(&mut *transaction).await?,
        group_client_traffic_policies: GroupClientTrafficPolicies::load(&mut *transaction).await?,
    };

    let mut settings = before.settings.clone();
    let group_client_traffic_policies = match patch.apply(&mut settings) {
        Some(mut policies) => {
            policies
                .canonicalize()
                .map_err(|err| WebError::BadRequest(err.to_string()))?;
            if policies != before.group_client_traffic_policies {
                policies
                    .replace_all(&mut transaction)
                    .await
                    .map_err(|err| match err {
                        ReplaceGroupPoliciesError::Invalid(err) => {
                            WebError::BadRequest(err.to_string())
                        }
                        ReplaceGroupPoliciesError::Database(err) => err.into(),
                    })?;
            }
            policies
        }
        None => before.group_client_traffic_policies.clone(),
    };
    let after = ClientSettingsInfo {
        settings,
        group_client_traffic_policies,
    };
    if after == before {
        transaction.rollback().await?;
        return Ok(ApiResponse::json(after, StatusCode::OK));
    }
    if after.settings != before.settings {
        after.settings.save(&mut *transaction).await?;
    }
    transaction.commit().await?;
    after.settings.clone().set_cached();
    info!("User {} updated client settings", session.user.username);

    if after.settings.display_download_step != before.settings.display_download_step
        || after.settings.display_password_reset != before.settings.display_password_reset
    {
        broadcast_public_settings(
            &appstate.pool,
            &Settings::get_current_settings(),
            &appstate.proxy_control_tx,
        )
        .await;
    }

    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ClientSettingsUpdated {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(after, StatusCode::OK))
}
