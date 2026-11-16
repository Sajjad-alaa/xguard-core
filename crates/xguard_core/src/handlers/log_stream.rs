//! Activity log streaming destinations (admin only). Every change is audited.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bytes::Bytes;
use serde::Serialize;
use serde_json::json;
use xguard_common::db::Id;

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    log_stream::{
        ActivityLogStream, StreamError, StreamInput,
        sender::{self, StreamStatus},
    },
};

impl From<StreamError> for WebError {
    fn from(err: StreamError) -> Self {
        match err {
            StreamError::Invalid(_) | StreamError::TooMany => Self::BadRequest(err.to_string()),
            StreamError::NotFound => Self::ObjectNotFound(err.to_string()),
            StreamError::Database(err) => err.into(),
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StreamWithStatus {
    #[serde(flatten)]
    pub stream: ActivityLogStream,
    pub status: StreamStatus,
}

/// List activity log streams with their delivery status
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/activity_log_stream",
    tag = "activity log",
    responses((status = 200, description = "Destinations; passwords are never returned.", body = [StreamWithStatus])),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn list_streams(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let streams: Vec<StreamWithStatus> = ActivityLogStream::all(&appstate.pool)
        .await?
        .into_iter()
        .map(|stream| StreamWithStatus {
            status: sender::status(stream.id),
            stream,
        })
        .collect();
    Ok(ApiResponse::json(streams, StatusCode::OK))
}

/// Add an activity log stream
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/activity_log_stream",
    tag = "activity log",
    request_body = StreamInput,
    responses(
        (status = 201, description = "Destination added; streaming starts at once.", body = ActivityLogStream),
        (status = 400, description = "Invalid destination, or too many.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn create_stream(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<StreamInput>,
) -> ApiResult {
    let mut transaction = appstate.pool.begin().await?;
    let stream = ActivityLogStream::create(&mut transaction, input).await?;
    transaction.commit().await?;
    sender::reload();
    info!(
        "User {} added activity log stream {}",
        session.user.username, stream.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ActivityLogStreamCreated {
            stream: stream.clone(),
        }),
    })?;
    Ok(ApiResponse::json(stream, StatusCode::CREATED))
}

/// Change an activity log stream
///
/// Leave `password` out to keep the stored one, or send an empty string to remove it.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/activity_log_stream/{id}",
    tag = "activity log",
    params(("id" = Id, Path, description = "Stream ID")),
    request_body = StreamInput,
    responses(
        (status = 200, description = "Destination changed.", body = ActivityLogStream),
        (status = 400, description = "Invalid destination.", body = ApiErrorResponse),
        (status = 404, description = "No such destination.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn update_stream(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(input): Json<StreamInput>,
) -> ApiResult {
    let before = ActivityLogStream::find_by_id(&appstate.pool, id)
        .await?
        .ok_or(StreamError::NotFound)?;
    let mut transaction = appstate.pool.begin().await?;
    let after = ActivityLogStream::update(&mut transaction, id, input).await?;
    transaction.commit().await?;
    sender::reload();
    info!(
        "User {} modified activity log stream {}",
        session.user.username, after.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ActivityLogStreamModified {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Remove an activity log stream
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/activity_log_stream/{id}",
    tag = "activity log",
    params(("id" = Id, Path, description = "Stream ID")),
    responses(
        (status = 200, description = "Destination removed."),
        (status = 404, description = "No such destination.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn delete_stream(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let stream = ActivityLogStream::delete(&appstate.pool, id).await?;
    sender::reload();
    info!(
        "User {} removed activity log stream {}",
        session.user.username, stream.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::ActivityLogStreamRemoved { stream }),
    })?;
    Ok(ApiResponse::default())
}

/// Send a test entry to a destination
///
/// Uses the settings in the request, which need not be saved. Leave `password` out and set
/// `id` in the query to use the stored password of an existing destination.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/activity_log_stream/test",
    tag = "activity log",
    request_body = StreamInput,
    responses(
        (status = 200, description = "The collector accepted the test entry."),
        (status = 400, description = "Invalid settings, or the collector refused it.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub(crate) async fn test_stream(
    _admin: AdminRole,
    session: SessionInfo,
    State(appstate): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<TestQuery>,
    Json(input): Json<StreamInput>,
) -> ApiResult {
    let stored_password = match query.id {
        Some(id) => ActivityLogStream::targets(&appstate.pool)
            .await?
            .into_iter()
            .find(|target| target.id == id)
            .and_then(|target| target.config.password),
        None => None,
    };
    let (_, _, config) = input.into_config(stored_password)?;
    let line = json!({
        "timestamp": chrono::Utc::now().naive_utc(),
        "event": "activity_log_stream_test",
        "description": "XGuard activity log stream test",
        "username": session.user.username,
    });
    let body = Bytes::from(format!("{line}\n"));
    let result = match sender::client_for(&config) {
        Ok(client) => sender::post(&client, &config, body).await,
        Err(err) => Err(err),
    };
    match result {
        Ok(()) => Ok(ApiResponse::default()),
        Err(err) => Ok(ApiResponse::new(
            json!({ "msg": format!("The test entry was not delivered: {err}") }),
            StatusCode::BAD_REQUEST,
        )),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct TestQuery {
    id: Option<Id>,
}
