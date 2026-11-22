use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use chrono::Utc;
use serde_json::json;
use sqlx::query_scalar;
use xguard_common::db::models::{Settings, gateway::Gateway, proxy::Proxy};

use thiserror::Error;

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    PgPool,
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    handlers::settings::broadcast_public_settings,
    log_file::read_log_tail,
    mail::{
        Attachment,
        templates::{self, SUPPORT_EMAIL_ADDRESS},
        xoauth2::{self, OAuthError, Provider, StartRequest},
    },
    server_config,
    support::dump_config,
};

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SmtpOAuthStartResponse {
    pub authorization_url: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SmtpOAuthCallbackRequest {
    pub state: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SmtpOAuthCallbackResponse {
    pub provider: Provider,
    pub sender: String,
}

fn oauth_error_response(err: OAuthError) -> ApiResponse {
    match err {
        OAuthError::NotConfigured(_)
        | OAuthError::Invalid(_)
        | OAuthError::BadState
        | OAuthError::Denied(_)
        | OAuthError::NoRefreshToken => {
            ApiResponse::new(json!({"msg": err.to_string()}), StatusCode::BAD_REQUEST)
        }
        OAuthError::Provider(_) | OAuthError::Http(_) => {
            ApiResponse::new(json!({"msg": err.to_string()}), StatusCode::BAD_GATEWAY)
        }
        OAuthError::Database(db_err) => {
            error!("SMTP OAuth database error: {db_err}");
            ApiResponse::new(
                json!({"msg": "Internal server error"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// Start server-managed OAuth 2.0 authorization (PKCE) for SMTP XOAUTH2
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/mail/oauth/start",
    tag = "settings",
    request_body = StartRequest,
    responses(
        (status = 200, description = "Authorization URL for the provider popup.", body = SmtpOAuthStartResponse),
        (status = 400, description = "Invalid OAuth settings or missing client secret.", body = ApiErrorResponse, example = json!({"msg": "Invalid SMTP OAuth settings: sender email address"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn smtp_oauth_start(
    _admin: AdminRole,
    session: SessionInfo,
    Json(request): Json<StartRequest>,
) -> ApiResult {
    debug!(
        "Admin {} starting SMTP OAuth flow for provider {:?}",
        session.user.username, request.provider
    );
    let settings = Settings::get_current_settings();
    match xoauth2::start(session.user.id, request, &settings) {
        Ok(url) => Ok(ApiResponse::json(
            SmtpOAuthStartResponse {
                authorization_url: url.into(),
            },
            StatusCode::OK,
        )),
        Err(err) => Ok(oauth_error_response(err)),
    }
}

/// Finish server-managed OAuth 2.0 authorization and save XOAUTH2 SMTP settings
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/mail/oauth/callback",
    tag = "settings",
    request_body = SmtpOAuthCallbackRequest,
    responses(
        (status = 200, description = "Mailbox connected for SMTP XOAUTH2.", body = SmtpOAuthCallbackResponse),
        (status = 400, description = "Invalid or expired state, denied authorization, or missing refresh token.", body = ApiErrorResponse, example = json!({"msg": "The authorization expired or was started by someone else; connect the mailbox again"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 502, description = "OAuth provider token request failed.", body = ApiErrorResponse, example = json!({"msg": "The provider refused the token request"})),
        (status = 500, description = "Internal server error.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn smtp_oauth_callback(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(request): Json<SmtpOAuthCallbackRequest>,
) -> ApiResult {
    debug!(
        "Admin {} finishing SMTP OAuth callback",
        session.user.username
    );
    let before = Settings::get_current_settings();
    match xoauth2::finish(
        &appstate.pool,
        session.user.id,
        &request.state,
        request.code.as_deref(),
        request.error.as_deref(),
    )
    .await
    {
        Ok(connected) => {
            let after = Settings::get_current_settings();
            if before.edge_public_settings_changed(&after) {
                broadcast_public_settings(&appstate.pool, &after, &appstate.proxy_control_tx).await;
            }
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::SmtpOAuthConnected {
                    provider: connected.provider.name().to_owned(),
                    sender: connected.sender.clone(),
                }),
            })?;
            Ok(ApiResponse::json(
                SmtpOAuthCallbackResponse {
                    provider: connected.provider,
                    sender: connected.sender,
                },
                StatusCode::OK,
            ))
        }
        Err(err) => Ok(oauth_error_response(err)),
    }
}

#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TestMail {
    pub to: String,
}

/// Send a test email to verify the SMTP configuration
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/mail/test",
    tag = "support",
    request_body = TestMail,
    responses(
        (status = 200, description = "Test email sent."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to send test email.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
        (status = 503, description = "SMTP is not configured.", body = ApiErrorResponse, example = json!({"msg": "SMTP is not configured", "code": "smtp_not_configured"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn test_mail(
    _admin: AdminRole,
    session: SessionInfo,
    State(appstate): State<AppState>,
    Json(data): Json<TestMail>,
) -> ApiResult {
    debug!(
        "User {} sending test mail to {}",
        session.user.username, data.to
    );

    let mut conn = appstate.pool.begin().await?;
    let result = templates::test_mail(&data.to, &mut conn, Some(&session.session.into())).await;

    Ok(match result {
        Ok(()) => {
            info!(
                "User {} sent test mail to {}",
                session.user.username, data.to
            );
            ApiResponse::with_status(StatusCode::OK)
        }
        Err(err) => {
            error!(
                "User {} failed to send test mail to {}: {err}",
                session.user.username, data.to
            );
            ApiResponse::with_status(StatusCode::SERVICE_UNAVAILABLE)
        }
    })
}

async fn read_logs() -> String {
    let Some(path) = &server_config().log_file else {
        return "Log file not configured".to_owned();
    };

    match read_log_tail(path).await {
        Ok(logs) => logs,
        Err(err) => {
            let msg = format!("Error dumping app logs: {err}");
            error!(msg);
            msg
        }
    }
}

/// Send the support data bundle to the xguard support address
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/mail/support",
    tag = "support",
    responses(
        (status = 200, description = "Support data sent."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to send support data.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
        (status = 503, description = "SMTP is not configured.", body = ApiErrorResponse, example = json!({"msg": "SMTP is not configured", "code": "smtp_not_configured"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn send_support_data(
    _admin: AdminRole,
    session: SessionInfo,
    State(appstate): State<AppState>,
) -> ApiResult {
    debug!("User {} sending support mail", session.user.username);

    let mut conn = appstate.pool.begin().await?;
    let proxies = Proxy::all(&mut *conn).await?;
    let gateways = Gateway::all(&mut *conn).await?;

    let components_info = json!({
        "proxies": proxies.iter().map(|p| json!({
            "id": p.id,
            "name": p.name,
            "version": p.version.as_deref().unwrap_or("unknown"),
            "address": p.address,
            "connected_at": p.connected_at
        })).collect::<Vec<_>>(),
        "gateways": gateways.iter().map(|g| json!({
            "id": g.id,
            "network_id": g.location_id,
            "version": g.version.as_deref().unwrap_or("unknown"),
            "address": g.address,
            "port": g.port,
            "certificate": g.certificate_serial,
            "name": g.name,
            "connected_at": g.connected_at,
        })).collect::<Vec<_>>(),
    });
    let now = Utc::now();
    let components_json =
        serde_json::to_vec(&components_info).unwrap_or(b"JSON formatting error".into());
    let components = Attachment::new(format!("xguard-components-{now}.json"), components_json);
    let config = dump_config(&mut conn)
        .await
        .unwrap_or(json!({"err": "Failed to dump configuration"}));
    let config = serde_json::to_vec_pretty(&config).unwrap_or(b"JSON formatting error".into());
    let config = Attachment::new(format!("xguard-support-data-{now}.json"), config);
    let logs = read_logs().await;
    let logs = Attachment::new(format!("xguard-logs-{now}.txt"), logs.into());

    let result = templates::support_data_mail(
        SUPPORT_EMAIL_ADDRESS,
        &mut conn,
        vec![components, config, logs],
    )
    .await;
    Ok(match result {
        Ok(()) => {
            info!("User {} sent support mail", session.user.username);
            ApiResponse::with_status(StatusCode::OK)
        }
        Err(err) => {
            error!("Error sending support mail: {err}");
            ApiResponse::new(
                json!({"error": err.to_string()}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    })
}

/// Errors arising from automated mail operations.
#[derive(Debug, Error)]
pub enum MailError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Template error: {0}")]
    Template(#[from] crate::mail::templates::TemplateError),
}

/// Send Gateway disconnect email to all admin users.
pub async fn send_gateway_disconnected_email(
    gateway_name: String,
    network_name: String,
    gateway_adress: &str,
    pool: &PgPool,
) {
    debug!("Sending Gateway disconnected mail to all admin users");
    let Ok(admin_emails) = get_admins_emails(pool).await else {
        error!("Failed to fetch admin emails");
        return;
    };
    let Ok(mut conn) = pool.acquire().await else {
        error!("Failed to acquire database connection");
        return;
    };
    for email in admin_emails {
        if let Err(err) = templates::gateway_disconnected_mail(
            &email,
            &mut conn,
            &gateway_name,
            gateway_adress,
            &network_name,
        )
        .await
        {
            error!("Failed to send Gateway disconnect notification to {email}: {err}");
        }
    }
}

/// Send Gateway reconnect email to all admin users.
pub async fn send_gateway_reconnected_email(
    gateway_name: &str,
    network_name: &str,
    gateway_adress: &str,
    pool: &PgPool,
) {
    debug!("Sending Gateway reconnect mail to all admin users");
    let Ok(admin_emails) = get_admins_emails(pool).await else {
        error!("Failed to fetch admin emails");
        return;
    };
    let Ok(mut conn) = pool.acquire().await else {
        error!("Failed to acquire database connection");
        return;
    };
    for email in admin_emails {
        if let Err(err) = templates::gateway_reconnected_mail(
            &email,
            &mut conn,
            gateway_name,
            gateway_adress,
            network_name,
        )
        .await
        {
            error!("Failed to send Gateway reconnect notification to {email}: {err}");
        }
    }
}

async fn get_admins_emails(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    debug!("Getting emails of active admins");
    query_scalar::<_, String>(
        "SELECT u.email \
        FROM \"user\" u \
        JOIN group_user gu oN gu.user_id = u.id JOIN \"group\" g ON gu.group_id = g.id \
        WHERE g.is_admin AND u.is_active",
    )
    .fetch_all(pool)
    .await
}
