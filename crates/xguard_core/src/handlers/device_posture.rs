//! Device posture policies API (admin only).
//!
//! - Every change goes to the activity log.
//! - When the policies of a location change, active sessions there are re-evaluated against
//!   the stored device snapshots (see [`crate::posture::worker`]). Locations that start or stop
//!   requiring posture get a gateway update, because their peers are then authorized per
//!   session.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use xguard_common::db::{
    Id,
    models::{
        Device, User, WireguardNetwork,
        device_posture::{DevicePosture, LocationPostures, PostureSnapshot},
    },
};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::AdminRole,
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    grpc::GatewayCommand,
    location_management::allowed_peers::get_location_allowed_peers,
    posture::{
        policy::{
            ApiDevicePosture, EditDevicePosture, MAX_NAME_LEN, PolicyError, VersionCatalog,
            normalize_ids,
        },
        worker::policies_changed,
    },
};

impl From<PolicyError> for WebError {
    fn from(err: PolicyError) -> Self {
        Self::BadRequest(err.0)
    }
}

async fn find_posture(conn: &mut PgConnection, id: Id) -> Result<ApiDevicePosture, WebError> {
    DevicePosture::find_with_rules(conn, id)
        .await?
        .map(ApiDevicePosture::from)
        .ok_or_else(|| WebError::ObjectNotFound(format!("Posture policy {id} not found")))
}

/// Gateway updates for locations whose need for posture changed: their peers switch between
/// "always allowed" and "allowed per authorized session". `before` lists the locations that had
/// policies before the change; `affected` every location the change touched.
async fn gateway_updates(
    conn: &mut PgConnection,
    affected: &[Id],
    before: &[Id],
) -> Result<Vec<GatewayCommand>, WebError> {
    let after = LocationPostures::with_postures(&mut *conn, affected).await?;
    let mut commands = Vec::new();
    for location_id in affected {
        if before.contains(location_id) == after.contains(location_id) {
            continue;
        }
        let Some(location) = WireguardNetwork::find_by_id(&mut *conn, *location_id).await? else {
            continue;
        };
        if location.mfa_enabled {
            // Peers of MFA locations are authorized per session either way.
            continue;
        }
        let peers = get_location_allowed_peers(&location, &mut *conn).await?;
        commands.push(GatewayCommand::NetworkModified(location, peers));
    }
    Ok(commands)
}

/// List posture policies
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device-posture",
    tag = "device posture",
    responses(
        (status = 200, description = "All posture policies, by name.", body = [ApiDevicePosture]),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn list_device_postures(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let mut conn = appstate.pool.acquire().await?;
    let postures: Vec<ApiDevicePosture> = DevicePosture::list_with_rules(&mut conn)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(ApiResponse::json(postures, StatusCode::OK))
}

/// Suggested versions for posture rules
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device-posture/versions",
    tag = "device posture",
    responses(
        (status = 200, description = "Version shortcuts for the web UI.", body = VersionCatalog),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn device_posture_versions(_admin: AdminRole) -> ApiResult {
    Ok(ApiResponse::json(VersionCatalog::new(), StatusCode::OK))
}

/// Get a posture policy
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device-posture/{id}",
    tag = "device posture",
    params(("id" = Id, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "The policy.", body = ApiDevicePosture),
        (status = 404, description = "No such policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn get_device_posture(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let mut conn = appstate.pool.acquire().await?;
    let posture = find_posture(&mut conn, id).await?;
    Ok(ApiResponse::json(posture, StatusCode::OK))
}

/// Create a posture policy
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/device-posture",
    tag = "device posture",
    request_body = EditDevicePosture,
    responses(
        (status = 201, description = "Policy created.", body = ApiDevicePosture),
        (status = 400, description = "Invalid policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn create_device_posture(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<EditDevicePosture>,
) -> ApiResult {
    let policy = input.validate()?;
    let mut transaction = appstate.pool.begin().await?;
    let posture = policy.posture.save(&mut transaction).await?;
    posture
        .replace_rules(&mut transaction, &policy.os_rules)
        .await?;
    let created = find_posture(&mut transaction, posture.id).await?;
    transaction.commit().await?;
    info!("Created posture policy {} ({})", created.name, created.id);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DevicePostureCreated {
            posture: created.clone(),
        }),
    })?;
    Ok(ApiResponse::json(created, StatusCode::CREATED))
}

/// Update a posture policy
///
/// Devices connected to the policy's locations are re-evaluated against their last posture
/// report and disconnected if they no longer comply.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/device-posture/{id}",
    tag = "device posture",
    params(("id" = Id, Path, description = "Policy ID")),
    request_body = EditDevicePosture,
    responses(
        (status = 200, description = "Policy updated.", body = ApiDevicePosture),
        (status = 400, description = "Invalid policy.", body = ApiErrorResponse),
        (status = 404, description = "No such policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn update_device_posture(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(input): Json<EditDevicePosture>,
) -> ApiResult {
    let policy = input.validate()?;
    let mut transaction = appstate.pool.begin().await?;
    let before = find_posture(&mut transaction, id).await?;
    let posture = DevicePosture {
        id,
        name: policy.posture.name,
        description: policy.posture.description,
        min_desktop_client_version: policy.posture.min_desktop_client_version,
        min_mobile_client_version: policy.posture.min_mobile_client_version,
        allow_prerelease_client: policy.posture.allow_prerelease_client,
    };
    posture.update(&mut transaction).await?;
    posture
        .replace_rules(&mut transaction, &policy.os_rules)
        .await?;
    let after = find_posture(&mut transaction, id).await?;
    transaction.commit().await?;
    if before == after {
        return Ok(ApiResponse::json(after, StatusCode::OK));
    }
    info!("Updated posture policy {} ({id})", after.name);
    policies_changed(after.locations.iter().copied());
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DevicePostureUpdated {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Delete a posture policy
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/device-posture/{id}",
    tag = "device posture",
    params(("id" = Id, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy deleted."),
        (status = 404, description = "No such policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn delete_device_posture(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let mut transaction = appstate.pool.begin().await?;
    let deleted = find_posture(&mut transaction, id).await?;
    let before = LocationPostures::with_postures(&mut *transaction, &deleted.locations).await?;
    let posture = DevicePosture::find_by_id(&mut *transaction, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Posture policy {id} not found")))?;
    posture.delete(&mut transaction).await?;
    let commands = gateway_updates(&mut transaction, &deleted.locations, &before).await?;
    transaction.commit().await?;
    appstate.send_multiple_gateway_commands(commands);
    // Removing a policy can only relax the remaining ones; nothing to re-evaluate.
    info!("Deleted posture policy {} ({id})", deleted.name);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DevicePostureDeleted { posture: deleted }),
    })?;
    Ok(ApiResponse::new(serde_json::Value::Null, StatusCode::OK))
}

/// The name of a copy: `<name> (copy)`, shortened to fit.
fn copy_name(name: &str) -> String {
    const SUFFIX: &str = " (copy)";
    let keep = MAX_NAME_LEN - SUFFIX.len();
    let base: String = name.chars().take(keep).collect();
    format!("{}{SUFFIX}", base.trim_end())
}

/// Duplicate a posture policy
///
/// The copy has the same rules and no locations.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/device-posture/{id}/duplicate",
    tag = "device posture",
    params(("id" = Id, Path, description = "Policy ID")),
    responses(
        (status = 201, description = "The copy.", body = ApiDevicePosture),
        (status = 404, description = "No such policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn duplicate_device_posture(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let mut transaction = appstate.pool.begin().await?;
    let original = DevicePosture::find_with_rules(&mut transaction, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Posture policy {id} not found")))?;
    let copy = DevicePosture {
        id: xguard_common::db::NoId,
        name: copy_name(&original.posture.name),
        description: original.posture.description.clone(),
        min_desktop_client_version: original.posture.min_desktop_client_version.clone(),
        min_mobile_client_version: original.posture.min_mobile_client_version.clone(),
        allow_prerelease_client: original.posture.allow_prerelease_client,
    }
    .save(&mut transaction)
    .await?;
    copy.replace_rules(&mut transaction, &original.os_rules)
        .await?;
    let duplicate = find_posture(&mut transaction, copy.id).await?;
    transaction.commit().await?;
    info!(
        "Duplicated posture policy {} as {} ({})",
        original.posture.name, duplicate.name, duplicate.id
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DevicePostureDuplicated {
            original: original.into(),
            duplicate: duplicate.clone(),
        }),
    })?;
    Ok(ApiResponse::json(duplicate, StatusCode::CREATED))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AssignLocations {
    pub locations: Vec<Id>,
}

/// Set the locations of a posture policy
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/device-posture/{id}/locations",
    tag = "device posture",
    params(("id" = Id, Path, description = "Policy ID")),
    request_body = AssignLocations,
    responses(
        (status = 200, description = "Locations set.", body = ApiDevicePosture),
        (status = 400, description = "Unknown location.", body = ApiErrorResponse),
        (status = 404, description = "No such policy.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn set_device_posture_locations(
    _admin: AdminRole,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(input): Json<AssignLocations>,
) -> ApiResult {
    let locations = normalize_ids(&input.locations)?;
    let mut transaction = appstate.pool.begin().await?;
    let posture = DevicePosture::find_by_id(&mut *transaction, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Posture policy {id} not found")))?;
    let existing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM wireguard_network WHERE id = ANY($1)")
            .bind(&locations)
            .fetch_one(&mut *transaction)
            .await?;
    if usize::try_from(existing).ok() != Some(locations.len()) {
        return Err(WebError::BadRequest("Unknown location.".into()));
    }
    let current = posture.location_ids(&mut *transaction).await?;
    if current == locations {
        let unchanged = find_posture(&mut transaction, id).await?;
        return Ok(ApiResponse::json(unchanged, StatusCode::OK));
    }
    let mut affected = current.clone();
    affected.extend(locations.iter().copied());
    affected.sort_unstable();
    affected.dedup();
    let before = LocationPostures::with_postures(&mut *transaction, &affected).await?;
    posture.set_locations(&mut transaction, &locations).await?;
    let commands = gateway_updates(&mut transaction, &affected, &before).await?;
    let updated = find_posture(&mut transaction, id).await?;
    transaction.commit().await?;
    appstate.send_multiple_gateway_commands(commands);
    // Only newly attached locations can get stricter.
    policies_changed(locations.iter().copied().filter(|l| !current.contains(l)));
    info!(
        "Assigned posture policy {} ({id}) to locations {locations:?}",
        posture.name
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::DevicePostureLocationsAssigned {
            posture_id: id,
            posture_name: posture.name,
            location_ids: locations,
        }),
    })?;
    Ok(ApiResponse::json(updated, StatusCode::OK))
}

/// A device's last posture report, for admins.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DevicePostureView {
    pub device_id: Id,
    pub device_name: String,
    /// `None` when the device never reported posture.
    pub snapshot: Option<PostureSnapshot>,
}

/// Get the last posture report of a device
///
/// The facts are what the client reported about its device: an attestation, not proof.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device/{device_id}/posture",
    tag = "device posture",
    params(("device_id" = Id, Path, description = "Device ID")),
    responses(
        (status = 200, description = "The device's last posture report.", body = DevicePostureView),
        (status = 404, description = "No such device.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn get_device_posture_snapshot(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(device_id): Path<Id>,
) -> ApiResult {
    let device = Device::find_by_id(&appstate.pool, device_id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("device id {device_id} not found")))?;
    let snapshot = PostureSnapshot::find(&appstate.pool, device_id).await?;
    Ok(ApiResponse::json(
        DevicePostureView {
            device_id,
            device_name: device.name,
            snapshot,
        },
        StatusCode::OK,
    ))
}

/// Get the last posture reports of a user's devices
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/user/{username}/device-posture",
    tag = "device posture",
    params(("username" = String, Path, description = "Device owner")),
    responses(
        (status = 200, description = "Posture reports of the user's devices that have one.", body = [PostureSnapshot]),
        (status = 404, description = "No such user.", body = ApiErrorResponse),
    ),
    security(("cookie" = []), ("api_token" = []))
))]
pub async fn list_user_device_postures(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult {
    let user = User::find_by_username(&appstate.pool, &username)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("user {username} not found")))?;
    let snapshots = PostureSnapshot::find_for_user(&appstate.pool, user.id).await?;
    Ok(ApiResponse::json(snapshots, StatusCode::OK))
}

#[cfg(test)]
mod tests {
    use super::copy_name;

    #[test]
    fn copy_names_fit() {
        assert_eq!(copy_name("Laptops"), "Laptops (copy)");
        let long = "n".repeat(64);
        let copy = copy_name(&long);
        assert_eq!(copy.chars().count(), 64);
        assert!(copy.ends_with(" (copy)"));
    }
}
