//! Admin REST API for RADIUS MFA settings and connectivity testing.

use std::{net::IpAddr, time::Duration};

use axum::{Json, extract::State, http::StatusCode};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use xguard_common::db::models::radius::RadiusSettingsView;
use xguard_common::{
    db::models::radius::{RadiusSettings, RadiusUsernameFormat},
    secret::SecretStringWrapper,
};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    AppState,
    auth::AdminRole,
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    radius::client::{RadiusClientConfig, RadiusOutcome, RadiusServerConfig, authenticate},
};

/// Payload for `PUT /api/v1/settings/radius`.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateRadiusSettingsRequest {
    pub enabled: bool,
    pub web_login_enabled: bool,
    pub vpn_mfa_enabled: bool,
    pub primary_host: String,
    #[serde(default = "default_port")]
    pub primary_port: u16,
    /// Omit or leave empty to keep the existing primary shared secret.
    pub primary_secret: Option<String>,
    pub secondary_host: Option<String>,
    #[serde(default = "default_port")]
    pub secondary_port: u16,
    /// Omit or leave empty to keep the existing secondary shared secret.
    pub secondary_secret: Option<String>,
    #[serde(default)]
    pub clear_secondary_secret: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_retries")]
    pub retries: u8,
    #[serde(default = "default_nas_identifier")]
    pub nas_identifier: String,
    pub nas_ip_address: Option<String>,
    #[serde(default)]
    pub username_format: RadiusUsernameFormat,
    #[serde(default)]
    pub push_enabled: bool,
    #[serde(default = "default_poll_interval")]
    pub push_poll_interval_secs: u32,
}

fn default_port() -> u16 {
    1812
}
fn default_timeout() -> u64 {
    3
}
fn default_retries() -> u8 {
    3
}
fn default_nas_identifier() -> String {
    "xguard".to_owned()
}
fn default_poll_interval() -> u32 {
    2
}

const MAX_RADIUS_HOST_LEN: usize = 255;
const MAX_RADIUS_SECRET_LEN: usize = 256;
const MAX_RADIUS_NAS_ID_LEN: usize = 255;

fn is_blocked_radius_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_link_local() || v4.is_unspecified())
        }
    }
}

fn validate_radius_host(host: &str, label: &str) -> Result<(), WebError> {
    if host.len() > MAX_RADIUS_HOST_LEN {
        return Err(WebError::BadRequest(format!(
            "{label} must be at most {MAX_RADIUS_HOST_LEN} characters"
        )));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(WebError::BadRequest(format!(
            "{label} must not contain whitespace or control characters"
        )));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.eq_ignore_ascii_case("metadata.google.internal")
        || bare.eq_ignore_ascii_case("metadata.goog")
    {
        return Err(WebError::BadRequest(format!(
            "{label} cannot target cloud metadata endpoints"
        )));
    }
    if let Ok(ip) = bare.parse::<IpAddr>()
        && is_blocked_radius_ip(ip)
    {
        return Err(WebError::BadRequest(format!(
            "{label} cannot use a link-local or unspecified IP address"
        )));
    }
    Ok(())
}

fn validate_radius_secret(secret: &str, label: &str) -> Result<(), WebError> {
    if secret.len() > MAX_RADIUS_SECRET_LEN {
        return Err(WebError::BadRequest(format!(
            "{label} must be at most {MAX_RADIUS_SECRET_LEN} bytes"
        )));
    }
    Ok(())
}

/// Payload for `POST /api/v1/settings/radius/test`.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TestRadiusRequest {
    pub username: String,
    pub password: String,
    /// Optional overrides to test unsaved form values; falls back to stored settings.
    pub primary_host: Option<String>,
    pub primary_port: Option<u16>,
    pub primary_secret: Option<String>,
    pub secondary_host: Option<String>,
    pub secondary_port: Option<u16>,
    pub secondary_secret: Option<String>,
    pub timeout_secs: Option<u64>,
    pub retries: Option<u8>,
    pub nas_identifier: Option<String>,
    pub nas_ip_address: Option<String>,
}

/// Response from `POST /api/v1/settings/radius/test`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TestRadiusResponse {
    /// `"accept"`, `"reject"`, or `"challenge"`.
    pub decision: &'static str,
    pub reply_message: Option<String>,
    pub challenge: bool,
}

/// Get RADIUS MFA settings (secrets are never returned).
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/settings/radius",
    tag = "settings",
    responses(
        (status = 200, description = "RADIUS MFA settings.", body = RadiusSettingsView),
        (status = 401, description = "Unauthorized.", body = ApiErrorResponse),
        (status = 403, description = "Admin access required.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn get_radius_settings(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let settings = RadiusSettings::get(&appstate.pool).await?;
    Ok(ApiResponse::json(settings.to_view(), StatusCode::OK))
}

/// Update RADIUS MFA settings.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/settings/radius",
    tag = "settings",
    request_body = UpdateRadiusSettingsRequest,
    responses(
        (status = 200, description = "RADIUS MFA settings updated.", body = RadiusSettingsView),
        (status = 400, description = "Invalid RADIUS configuration.", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized.", body = ApiErrorResponse),
        (status = 403, description = "Admin access required.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn update_radius_settings(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(req): Json<UpdateRadiusSettingsRequest>,
) -> ApiResult {
    let existing = RadiusSettings::get(&appstate.pool).await?;

    let primary_host = req.primary_host.trim().to_owned();
    if !primary_host.is_empty() {
        validate_radius_host(&primary_host, "Primary RADIUS host")?;
    }
    if let Some(secret) = req.primary_secret.as_deref() {
        validate_radius_secret(secret, "Primary shared secret")?;
    }
    if let Some(secret) = req.secondary_secret.as_deref() {
        validate_radius_secret(secret, "Secondary shared secret")?;
    }
    let nas_identifier_trimmed = req.nas_identifier.trim();
    if nas_identifier_trimmed.len() > MAX_RADIUS_NAS_ID_LEN
        || nas_identifier_trimmed.chars().any(char::is_control)
    {
        return Err(WebError::BadRequest(format!(
            "NAS-Identifier must be at most {MAX_RADIUS_NAS_ID_LEN} printable characters"
        )));
    }
    if req.primary_port == 0 {
        return Err(WebError::BadRequest(
            "Primary port must be between 1 and 65535".into(),
        ));
    }
    if req.secondary_port == 0 {
        return Err(WebError::BadRequest(
            "Secondary port must be between 1 and 65535".into(),
        ));
    }
    if !(1..=30).contains(&req.timeout_secs) {
        return Err(WebError::BadRequest(
            "Timeout must be between 1 and 30 seconds".into(),
        ));
    }
    if !(1..=10).contains(&req.retries) {
        return Err(WebError::BadRequest(
            "Retries must be between 1 and 10".into(),
        ));
    }
    if !(1..=15).contains(&req.push_poll_interval_secs) {
        return Err(WebError::BadRequest(
            "Push poll interval must be between 1 and 15 seconds".into(),
        ));
    }

    let nas_ip_address = match req
        .nas_ip_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(
            raw.parse::<IpAddr>()
                .map_err(|_| WebError::BadRequest("Invalid NAS IP address".into()))?,
        ),
        None => None,
    };

    let primary_secret = match req.primary_secret.as_deref() {
        Some(s) if !s.is_empty() => SecretStringWrapper::from(s),
        _ => existing.primary_secret,
    };

    let secondary_host = req
        .secondary_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if let Some(host) = secondary_host.as_deref() {
        validate_radius_host(host, "Secondary RADIUS host")?;
    }

    let secondary_secret = if req.clear_secondary_secret || secondary_host.is_none() {
        None
    } else {
        match req.secondary_secret.as_deref() {
            Some(s) if !s.is_empty() => Some(SecretStringWrapper::from(s)),
            _ => existing.secondary_secret,
        }
    };

    if req.enabled && (primary_host.is_empty() || primary_secret.expose_secret().is_empty()) {
        return Err(WebError::BadRequest(
            "Primary RADIUS host and shared secret are required when RADIUS MFA is enabled".into(),
        ));
    }

    let updated = RadiusSettings {
        enabled: req.enabled,
        web_login_enabled: req.web_login_enabled,
        vpn_mfa_enabled: req.vpn_mfa_enabled,
        primary_host,
        primary_port: req.primary_port,
        primary_secret,
        secondary_host,
        secondary_port: req.secondary_port,
        secondary_secret,
        timeout_secs: req.timeout_secs,
        retries: req.retries,
        nas_identifier: if req.nas_identifier.trim().is_empty() {
            "xguard".to_owned()
        } else {
            req.nas_identifier.trim().to_owned()
        },
        nas_ip_address,
        username_format: req.username_format,
        push_enabled: req.push_enabled,
        push_poll_interval_secs: req.push_poll_interval_secs,
    };

    updated.save(&appstate.pool).await?;

    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::RadiusSettingsUpdated {
            enabled: updated.enabled,
            web_login_enabled: updated.web_login_enabled,
            vpn_mfa_enabled: updated.vpn_mfa_enabled,
            primary_host: updated.primary_host.clone(),
        }),
    })?;

    Ok(ApiResponse::json(updated.to_view(), StatusCode::OK))
}

/// Send a test RADIUS Access-Request using submitted or stored server settings.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/settings/radius/test",
    tag = "settings",
    request_body = TestRadiusRequest,
    responses(
        (status = 200, description = "RADIUS server responded.", body = TestRadiusResponse),
        (status = 400, description = "Invalid request or missing RADIUS config.", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized.", body = ApiErrorResponse),
        (status = 403, description = "Admin access required.", body = ApiErrorResponse),
        (status = 502, description = "RADIUS server unreachable.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn test_radius_settings(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Json(req): Json<TestRadiusRequest>,
) -> ApiResult {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(WebError::BadRequest("Test username is required".into()));
    }

    let stored = RadiusSettings::get(&appstate.pool).await?;
    let primary_host = req
        .primary_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| stored.primary_host.clone(), str::to_owned);
    let primary_secret = req
        .primary_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || stored.primary_secret.expose_secret().to_owned(),
            str::to_owned,
        );

    if primary_host.is_empty() || primary_secret.is_empty() {
        return Err(WebError::BadRequest(
            "Primary RADIUS host and shared secret are required to run a test".into(),
        ));
    }
    validate_radius_host(&primary_host, "Primary RADIUS host")?;
    validate_radius_secret(&primary_secret, "Primary shared secret")?;

    let secondary_host = req
        .secondary_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or(stored.secondary_host);
    if let Some(host) = secondary_host.as_deref() {
        validate_radius_host(host, "Secondary RADIUS host")?;
    }
    let secondary_secret = req
        .secondary_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            stored
                .secondary_secret
                .map(|s| s.expose_secret().to_owned())
        });

    let nas_ip_address = match req.nas_ip_address.as_deref().map(str::trim) {
        Some("") => None,
        Some(raw) => Some(
            raw.parse::<IpAddr>()
                .map_err(|_| WebError::BadRequest("Invalid NAS IP address".into()))?,
        ),
        None => stored.nas_ip_address,
    };

    let cfg = RadiusClientConfig {
        primary: RadiusServerConfig {
            host: primary_host,
            port: req.primary_port.unwrap_or(stored.primary_port),
            secret: SecretString::from(primary_secret.clone()),
        },
        secondary: secondary_host.map(|host| RadiusServerConfig {
            host,
            port: req.secondary_port.unwrap_or(stored.secondary_port),
            secret: SecretString::from(
                secondary_secret
                    .filter(|s| !s.is_empty())
                    .unwrap_or(primary_secret),
            ),
        }),
        timeout: Duration::from_secs(req.timeout_secs.unwrap_or(stored.timeout_secs).clamp(1, 30)),
        retries: req.retries.unwrap_or(stored.retries).clamp(1, 10),
        nas_identifier: req
            .nas_identifier
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or(stored.nas_identifier, str::to_owned),
        nas_ip_address,
    };

    match authenticate(&cfg, username, &req.password, None).await {
        Ok(RadiusOutcome::Accept { reply_message }) => Ok(ApiResponse::json(
            TestRadiusResponse {
                decision: "accept",
                reply_message,
                challenge: false,
            },
            StatusCode::OK,
        )),
        Ok(RadiusOutcome::Reject { reply_message }) => Ok(ApiResponse::json(
            TestRadiusResponse {
                decision: "reject",
                reply_message,
                challenge: false,
            },
            StatusCode::OK,
        )),
        Ok(RadiusOutcome::Challenge { reply_message, .. }) => Ok(ApiResponse::json(
            TestRadiusResponse {
                decision: "challenge",
                reply_message,
                challenge: true,
            },
            StatusCode::OK,
        )),
        Err(err) => Err(WebError::BadRequest(format!("RADIUS test failed: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_radius_hosts_and_secrets() {
        assert!(validate_radius_host("radius.corp.internal", "Primary").is_ok());
        assert!(validate_radius_host("10.0.1.50", "Primary").is_ok());
        assert!(validate_radius_host("127.0.0.1", "Primary").is_ok());
        assert!(validate_radius_host("[::1]", "Primary").is_ok());

        for blocked in [
            "169.254.169.254",
            "0.0.0.0",
            "fe80::1",
            "[fe80::1]",
            "::",
            "::ffff:169.254.169.254",
            "metadata.google.internal",
            "metadata.goog",
            "radius.local host",
            "radius\n.local",
        ] {
            assert!(
                validate_radius_host(blocked, "Primary").is_err(),
                "expected {blocked} to be rejected"
            );
        }
        assert!(validate_radius_host(&"a".repeat(256), "Primary").is_err());
        assert!(validate_radius_secret(&"s".repeat(256), "Secret").is_ok());
        assert!(validate_radius_secret(&"s".repeat(257), "Secret").is_err());
    }
}
