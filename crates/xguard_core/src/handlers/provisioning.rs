//! Desktop client provisioning files.
//!
//! An admin generates a provisioning file for a user and deploys it to the user's computer (for
//! example with an MDM tool). The XGuard desktop client finds it at start-up and enrolls the
//! device without the user typing a URL or token.
//!
//! The file never carries a long-lived secret: it holds a single-use desktop activation token
//! that expires after a few hours (1 to 168, default 24). The device's WireGuard keys and polling
//! token are generated during enrollment and never leave the device. Generating a file replaces
//! the user's other unused enrollment tokens, as starting a desktop activation does.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use xguard_common::db::models::{Settings, user::User};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    enrollment_management::start_desktop_configuration,
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

/// Version of the provisioning file format.
pub const PROVISIONING_FILE_VERSION: u32 = 1;
const DEFAULT_VALID_HOURS: u32 = 24;
const MAX_VALID_HOURS: u32 = 168;

#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProvisioningRequest {
    /// Hours the enrollment token stays valid, 1-168 (default 24).
    #[serde(default)]
    pub valid_hours: Option<u32>,
}

/// The provisioning file read by the desktop client.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisioningFile {
    pub version: u32,
    pub instance_name: String,
    /// Public Edge URL the client enrolls through.
    pub enrollment_url: String,
    /// Single-use desktop activation token.
    pub enrollment_token: String,
    /// RFC 3339 UTC time after which the token no longer works.
    pub expires_at: String,
    pub username: String,
}

fn valid_hours(request: &ProvisioningRequest) -> Result<u32, WebError> {
    match request.valid_hours {
        None => Ok(DEFAULT_VALID_HOURS),
        Some(hours) if (1..=MAX_VALID_HOURS).contains(&hours) => Ok(hours),
        Some(_) => Err(WebError::BadRequest(format!(
            "valid_hours must be between 1 and {MAX_VALID_HOURS}"
        ))),
    }
}

/// Create a desktop client provisioning file
///
/// Returns a provisioning file for the user's next desktop client. Deploy it as
/// `provisioning.json` to the path documented for the client's operating system.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/user/{username}/provisioning",
    tag = "user",
    params(("username" = String, Path, description = "Name of the user.")),
    request_body = ProvisioningRequest,
    responses(
        (status = 201, description = "Provisioning file.", body = ProvisioningFile),
        (status = 400, description = "Invalid request or disabled user.", body = ApiErrorResponse),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
        (status = 404, description = "User not found.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn create_provisioning_file(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(username): Path<String>,
    Json(request): Json<ProvisioningRequest>,
) -> ApiResult {
    let hours = valid_hours(&request)?;
    let user = User::find_by_username(&appstate.pool, &username)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("user {username} not found")))?;
    if !user.is_active {
        return Err(WebError::BadRequest(format!(
            "Can't create a provisioning file for disabled user {username}"
        )));
    }

    let settings = Settings::get_current_settings();
    let enrollment_url = settings.proxy_public_url()?;
    let expires_at = Utc::now() + Duration::hours(i64::from(hours));
    let mut transaction = appstate.pool.begin().await?;
    let token = start_desktop_configuration(
        &user,
        &mut transaction,
        &session.user,
        None,
        u64::from(hours) * 3600,
        enrollment_url.clone(),
        false,
        None,
    )
    .await?;
    transaction.commit().await?;

    info!(
        "User {} created a desktop client provisioning file for {username}, valid for {hours} h",
        session.user.username
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ProvisioningFileCreated {
            user: user.clone(),
            expires_at: expires_at.naive_utc(),
        }),
    })?;

    let file = ProvisioningFile {
        version: PROVISIONING_FILE_VERSION,
        instance_name: settings.instance_name.clone(),
        enrollment_url: enrollment_url.to_string(),
        enrollment_token: token,
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        username: user.username,
    };
    Ok(ApiResponse::json(file, StatusCode::CREATED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hours_bounds() {
        let request = |valid_hours| ProvisioningRequest { valid_hours };
        assert_eq!(valid_hours(&request(None)).unwrap(), DEFAULT_VALID_HOURS);
        assert_eq!(valid_hours(&request(Some(1))).unwrap(), 1);
        assert_eq!(valid_hours(&request(Some(168))).unwrap(), 168);
        assert!(valid_hours(&request(Some(0))).is_err());
        assert!(valid_hours(&request(Some(169))).is_err());
    }
}
