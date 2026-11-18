use std::collections::HashSet;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
};
use ipnetwork::IpNetwork;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool, error::ErrorKind};
use xguard_common::{
    csv::AsCsv,
    db::{
        Id,
        models::{
            Device, DeviceConfig, DeviceType, User, WireguardNetwork,
            device::{AddDevice, DeviceInfo, ModifyDevice, WireguardNetworkDevice},
            device_posture::LocationPostures,
            mfa_flow::{LocationMfaFlowAssignment, MfaFlow, MfaFlowAssignmentLicenseError},
            wireguard::{GroupClientMtu, MappedDevice, ServiceLocationMode},
        },
    },
    utils::parse_network_address_list,
};

use super::{ApiResponse, ApiResult, WebError, device_for_admin_or_self, user_for_admin_or_self};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    device_access::{
        build_device_config, build_device_config_with_group_mtus, join_device_to_all_networks,
    },
    device_policy::{
        ONLY_CLIENT_ACTIVATION_MSG, ensure_may_configure_manually, ensure_may_manage_devices,
    },
    events::{ApiEvent, ApiEventType, ApiRequestContext},
    grpc::GatewayCommand,
    handlers::{
        gateway::GatewayInfo,
        mfa_flow::{assignment_error_response, license_error_response},
        network_devices::DeviceWireGuardConfig,
    },
    location_management::{
        allowed_peers::get_location_allowed_peers, handle_imported_devices, handle_mapped_devices,
        sync_location_allowed_devices,
    },
    mail::templates::{TemplateLocation, new_device_added_mail},
    wg_config::{ImportedDevice, parse_wireguard_config},
};

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct WireguardNetworkInfo {
    #[serde(flatten)]
    network: WireguardNetwork<Id>,
    gateways: Vec<GatewayInfo>,
    allowed_groups: Vec<String>,
    has_devices: bool,
    /// IDs of the posture policies attached to the location.
    posture_checks: Vec<Id>,
    group_client_mtus: Vec<GroupClientMtu>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct LocationsCount {
    count: usize,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WireguardNetworkData {
    pub name: String,
    pub address: String, // comma-separated list of addresses
    pub endpoint: String,
    pub port: i32,
    pub allowed_ips: Option<String>,
    pub dns: Option<String>,
    pub mtu: i32,
    pub fwmark: i64,
    /// If set, the XGuard Client should use this MTU.
    #[serde(default)]
    pub client_mtu: Option<i32>,
    pub allow_all_groups: bool,
    pub allowed_groups: Vec<String>,
    pub keepalive_interval: i32,
    pub peer_disconnect_threshold: i32,
    pub acl_enabled: bool,
    pub acl_default_allow: bool,
    #[serde(default)]
    pub allowed_ips_from_acl: bool,
    pub mfa_enabled: bool,
    pub service_location_mode: ServiceLocationMode,
    /// Posture policies to attach. `None` (absent) keeps the current ones.
    #[serde(default)]
    pub posture_checks: Option<Vec<Id>>,
    pub mfa_flows: Vec<LocationMfaFlowAssignment>,
    /// Client MTU overrides; each group may appear once. `None` keeps saved overrides.
    #[serde(default)]
    pub group_client_mtus: Option<Vec<GroupClientMtu>>,
}

const MIN_PEER_DISCONNECT_THRESHOLD_WITH_MFA: i32 = 120;

/// Normalises a list of posture policy IDs and checks that they all exist.
async fn validate_posture_assignment(
    conn: &mut PgConnection,
    ids: &[Id],
) -> Result<Result<Vec<Id>, ApiResponse>, WebError> {
    let ids = match crate::posture::policy::normalize_ids(ids) {
        Ok(ids) => ids,
        Err(err) => return Ok(Err(WebError::BadRequest(err.to_string()).into())),
    };
    let existing = LocationPostures::count_existing(&mut *conn, &ids).await?;
    if usize::try_from(existing).ok() != Some(ids.len()) {
        return Ok(Err(
            WebError::BadRequest("Unknown posture policy.".into()).into()
        ));
    }
    Ok(Ok(ids))
}
/// Smallest MTU WireGuard can carry a packet over.
const MIN_MTU: i32 = 72;
/// The largest MTU an IPv4/IPv6 interface can have.
const MAX_MTU: i32 = 65535;
/// Bounds the work one location update can cause.
const MAX_GROUP_MTU_ASSIGNMENTS: usize = 10_000;

/// Build the structured `400` response for the `mfa_enabled` precondition: a location cannot be
/// MFA-enabled while no MFA flow exists to assign to it.
///
/// The body is a real structured `validation_failed` payload, not a string inside `msg`, so the
/// frontend parses it in one step like every other validation path in this feature.
#[must_use]
pub fn no_flows_exist_response() -> ApiResponse {
    ApiResponse::new(
        json!({
            "error": "validation_failed",
            "fields": [{"field": "mfa_enabled", "code": "no_flows_exist"}]
        }),
        StatusCode::BAD_REQUEST,
    )
}

/// Build the structured `400` response for the `mfa_enabled` precondition when the location has no
/// default flow assigned: MFA cannot be enabled until a policy exists to enforce.
#[must_use]
pub fn no_flows_assigned_response() -> ApiResponse {
    ApiResponse::new(
        json!({
            "error": "validation_failed",
            "fields": [{"field": "mfa_enabled", "code": "no_flows_assigned"}]
        }),
        StatusCode::BAD_REQUEST,
    )
}

/// Validate enabling MFA on an already-persisted location.
///
/// When called on the transaction that saved `mfa_enabled`, after the save, the saved row stays
/// locked until commit, so a concurrent `MfaFlow::check_deletable` cannot remove the default in
/// between. Returns a structured `400` response (not a `WebError`) when no MFA flow or no
/// default assignment exists.
pub async fn validate_mfa_flows_exist(
    conn: &mut PgConnection,
    mfa_enabled: bool,
    location_id: Option<Id>,
) -> Result<Option<ApiResponse>, WebError> {
    if !mfa_enabled {
        return Ok(None);
    }

    if !MfaFlow::any_exist(&mut *conn).await? {
        error!("Unable to enable MFA for location: no MFA flows are configured");
        return Ok(Some(no_flows_exist_response()));
    }

    let has_default = match location_id {
        Some(id) => MfaFlow::has_default_assignment(&mut *conn, id).await?,
        None => false,
    };
    if !has_default {
        error!("Unable to enable MFA for location: no default MFA flow is assigned");
        return Ok(Some(no_flows_assigned_response()));
    }

    Ok(None)
}

impl WireguardNetworkData {
    pub(crate) fn parse_allowed_ips(&self) -> Vec<IpNetwork> {
        self.allowed_ips
            .as_ref()
            .map_or(Vec::new(), |ips| parse_network_address_list(ips))
    }

    pub(crate) fn validate_peer_disconnect_threshold(&self) -> Result<(), WebError> {
        if !self.mfa_enabled {
            return Ok(());
        }

        if self.peer_disconnect_threshold >= MIN_PEER_DISCONNECT_THRESHOLD_WITH_MFA {
            return Ok(());
        }

        Err(WebError::BadRequest(format!(
            "peer_disconnect_threshold must be at least {MIN_PEER_DISCONNECT_THRESHOLD_WITH_MFA} when location MFA is enabled"
        )))
    }

    /// Rejects service-location mode combined with location MFA: core cannot serve it and the
    /// client cannot represent it (`Location::is_service_location()` requires MFA disabled).
    pub(crate) fn validate_service_location_mfa(&self) -> Result<(), WebError> {
        if self.service_location_mode == ServiceLocationMode::Disabled {
            return Ok(());
        }
        if self.mfa_enabled {
            return Err(WebError::BadRequest(
                "Service location mode cannot be combined with location MFA".into(),
            ));
        }
        // A service location runs without a user session, so nothing could report posture.
        if self
            .posture_checks
            .as_deref()
            .is_some_and(|checks| !checks.is_empty())
        {
            return Err(WebError::BadRequest(
                "Service location mode cannot be combined with posture policies".into(),
            ));
        }
        Ok(())
    }

    /// Rejects a zero (or negative) keepalive interval to prevent idle service locations
    /// from disconnecting.
    pub(crate) fn validate_keepalive_interval(&self) -> Result<(), WebError> {
        if self.keepalive_interval >= 1 {
            return Ok(());
        }

        Err(WebError::BadRequest(
            "keepalive_interval must be at least 1".into(),
        ))
    }

    /// Rejects a client MTU below the WireGuard minimum; `None` means the client picks its own.
    pub(crate) fn validate_client_mtu(&self) -> Result<(), WebError> {
        self.client_mtu
            .map_or(Ok(()), |mtu| validate_min_mtu("client_mtu", mtu))
    }

    /// Each group may have only one override.
    pub(crate) fn validate_group_client_mtus(&self) -> Result<(), WebError> {
        let mut group_ids = HashSet::new();
        for item in self.group_client_mtus.iter().flatten() {
            validate_min_mtu("group_client_mtus: client_mtu", item.client_mtu)?;
            if item.group_ids.is_empty() {
                return Err(WebError::BadRequest(
                    "group_client_mtus: at least one group must be specified".into(),
                ));
            }
            for group_id in &item.group_ids {
                if group_ids.len() >= MAX_GROUP_MTU_ASSIGNMENTS {
                    return Err(WebError::BadRequest(format!(
                        "group_client_mtus: at most {MAX_GROUP_MTU_ASSIGNMENTS} groups"
                    )));
                }
                if !group_ids.insert(*group_id) {
                    return Err(WebError::BadRequest(format!(
                        "group_client_mtus: group {group_id} has more than one override"
                    )));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_allowed_groups(&self) -> Result<(), WebError> {
        if self.allow_all_groups || !self.allowed_groups.is_empty() {
            Ok(())
        } else {
            Err(WebError::BadRequest(
                "At least one group must be specified when allow_all_groups is disabled".into(),
            ))
        }
    }
}

fn validate_min_mtu(field: &str, mtu: i32) -> Result<(), WebError> {
    if mtu < MIN_MTU {
        Err(WebError::BadRequest(format!(
            "{field} must be at least {MIN_MTU}"
        )))
    } else if mtu > MAX_MTU {
        Err(WebError::BadRequest(format!(
            "{field} must be at most {MAX_MTU}"
        )))
    } else {
        Ok(())
    }
}

/// Unknown groups are rejected with `400`.
async fn save_group_client_mtus(
    network: &WireguardNetwork<Id>,
    conn: &mut PgConnection,
    overrides: &[GroupClientMtu],
) -> Result<(), WebError> {
    match network.set_group_client_mtus(conn, overrides).await {
        Err(sqlx::Error::Database(error)) if error.kind() == ErrorKind::ForeignKeyViolation => Err(
            WebError::BadRequest("group_client_mtus: unknown group specified".into()),
        ),
        result => Ok(result?),
    }
}

// Used in process of importing network from WireGuard config.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct MappedDevices {
    devices: Vec<MappedDevice>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct ImportNetworkData {
    name: String,
    endpoint: String,
    config: String,
    allow_all_groups: bool,
    allowed_groups: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportedNetworkData {
    pub network: WireguardNetwork<Id>,
    pub devices: Vec<ImportedDevice>,
}

fn assignment_license_error_response(
    error: MfaFlowAssignmentLicenseError,
) -> Result<ApiResponse, WebError> {
    let code = match error {
        MfaFlowAssignmentLicenseError::GroupAssignmentNotAllowed => "group_assignment_not_allowed",
        MfaFlowAssignmentLicenseError::MultipleStepsNotAllowed => "multiple_steps_not_allowed",
        MfaFlowAssignmentLicenseError::MultipleMfaFlowsNotAllowed => {
            "multiple_mfa_flows_not_allowed"
        }
        MfaFlowAssignmentLicenseError::Database(error) => return Err(WebError::from(error)),
    };
    Ok(license_error_response("mfa_flows", code))
}

/// Prepare assignments for equality check.
fn normalize_mfa_flow_assignments(
    mut assignments: Vec<LocationMfaFlowAssignment>,
) -> Vec<LocationMfaFlowAssignment> {
    for assignment in &mut assignments {
        assignment.group_ids.sort_unstable();
    }
    assignments
}

/// Create a network
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/network",
    tag = "network",
    request_body(content = WireguardNetworkData, description = "`address` is a comma-separated list of network addresses.", example = json!({"name": "office", "address": "10.0.0.1/24", "endpoint": "vpn.example.com", "port": 50051, "allowed_ips": "0.0.0.0/0", "dns": "1.1.1.1", "mtu": 1420, "fwmark": 0, "client_mtu": null, "allow_all_groups": true, "allowed_groups": [], "keepalive_interval": 25, "peer_disconnect_threshold": 180, "acl_enabled": false, "acl_default_allow": false, "allowed_ips_from_acl": false, "mfa_enabled": false, "service_location_mode": "disabled"})),
    responses(
        (status = 201, description = "Network created.", body = WireguardNetwork),
        (status = 400, description = "Invalid location settings.", body = ApiErrorResponse, example = json!({"msg": "At least one group must be specified when allow_all_groups is disabled"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 500, description = "Unable to create network.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn create_network(
    _role: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
    Json(data): Json<WireguardNetworkData>,
) -> ApiResult {
    let network_name = data.name.clone();
    debug!(
        "User {} creating WireGuard network {network_name}",
        session.user.username
    );

    data.validate_peer_disconnect_threshold()?;
    data.validate_service_location_mfa()?;
    data.validate_keepalive_interval()?;
    data.validate_client_mtu()?;
    data.validate_allowed_groups()?;
    data.validate_group_client_mtus()?;

    let allowed_ips = data.parse_allowed_ips();
    let mut network = WireguardNetwork::new(
        data.name,
        data.port,
        data.endpoint,
        data.dns,
        allowed_ips,
        data.allow_all_groups,
        data.acl_enabled,
        data.acl_default_allow,
        data.allowed_ips_from_acl,
        data.mfa_enabled,
        data.service_location_mode,
    )
    .try_set_address(&data.address)?;
    network.mtu = data.mtu;
    network.fwmark = data.fwmark;
    network.client_mtu = data.client_mtu;
    network.keepalive_interval = data.keepalive_interval;
    network.peer_disconnect_threshold = data.peer_disconnect_threshold;

    let mut transaction = appstate.pool.begin().await?;
    let network = network.save(&mut *transaction).await?;
    network
        .set_allowed_groups(&mut transaction, &data.allowed_groups)
        .await?;
    let group_mtus_after = if let Some(overrides) = &data.group_client_mtus {
        save_group_client_mtus(&network, &mut transaction, overrides).await?;
        network.fetch_group_client_mtus(&mut *transaction).await?
    } else {
        Vec::new()
    };

    // generate IP addresses for existing devices
    network.add_all_allowed_devices(&mut transaction).await?;
    info!("Assigning IPs for existing devices in network {network}");

    let posture_checks = match validate_posture_assignment(
        &mut transaction,
        data.posture_checks.as_deref().unwrap_or_default(),
    )
    .await?
    {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    LocationPostures::set(&mut transaction, network.id, &posture_checks).await?;

    let mfa_assignments: Vec<LocationMfaFlowAssignment> = data.mfa_flows.clone();
    if let Err(error) = MfaFlow::validate_mfa_flow_assignments_license(
        &mut transaction,
        &mfa_assignments,
        true,
        true,
    )
    .await
    {
        return assignment_license_error_response(error);
    }
    if let Err(error) =
        MfaFlow::assign_to_location(&mut transaction, network.id, &mfa_assignments).await
    {
        return assignment_error_response(&data.mfa_flows, error);
    }
    transaction.commit().await?;

    appstate.send_gateway_command(GatewayCommand::NetworkCreated(network.clone()));

    info!(
        "User {} created WireGuard network {network_name}",
        session.user.username
    );

    if !posture_checks.is_empty() {
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationPosturesAssigned {
                location_id: network.id,
                location_name: network.name.clone(),
                posture_ids: posture_checks,
            }),
        })?;
    }
    if !mfa_assignments.is_empty() {
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationMfaFlowsAssigned {
                location_id: network.id,
                location_name: network.name.clone(),
                assignments: LocationMfaFlowAssignment::snapshot(&mfa_assignments),
            }),
        })?;
    }
    if !group_mtus_after.is_empty() {
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationGroupMtusChanged {
                location_id: network.id,
                location_name: network.name.clone(),
                before: Vec::new(),
                after: group_mtus_after,
            }),
        })?;
    }
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::VpnLocationAdded {
            location: network.clone(),
        }),
    })?;

    Ok(ApiResponse::json(network, StatusCode::CREATED))
}

async fn find_network(id: Id, pool: &PgPool) -> Result<WireguardNetwork<Id>, WebError> {
    WireguardNetwork::find_by_id(pool, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Network {id} not found")))
}

/// Update a network
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/network/{network_id}",
    tag = "network",
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
    ),
    request_body = WireguardNetworkData,
    responses(
        (status = 200, description = "Network updated.", body = WireguardNetwork),
        (status = 400, description = "Invalid location settings.", body = ApiErrorResponse, example = json!({"msg": "Enterprise license required."})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 404, description = "Network not found.", body = ApiErrorResponse, example = json!({"msg": "network not found"})),
        (status = 500, description = "Unable to update network.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn modify_network(
    _role: AdminRole,
    Path(network_id): Path<Id>,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
    Json(data): Json<WireguardNetworkData>,
) -> ApiResult {
    debug!(
        "User {} updating WireGuard network {network_id}",
        session.user.username
    );

    data.validate_peer_disconnect_threshold()?;
    data.validate_service_location_mfa()?;
    data.validate_keepalive_interval()?;
    data.validate_client_mtu()?;
    data.validate_allowed_groups()?;
    data.validate_group_client_mtus()?;

    let network = find_network(network_id, &appstate.pool).await?;
    // store network before mods
    let before = network.clone();
    let mut network = network.try_set_address(&data.address)?;
    network.allowed_ips = data.parse_allowed_ips();
    network.name = data.name;

    // initialize DB transaction
    let mut transaction = appstate.pool.begin().await?;

    network.endpoint = data.endpoint;
    network.port = data.port;
    network.dns = data.dns;
    network.keepalive_interval = data.keepalive_interval;
    network.mtu = data.mtu;
    network.fwmark = data.fwmark;
    network.client_mtu = data.client_mtu;
    network.peer_disconnect_threshold = data.peer_disconnect_threshold;
    network.allow_all_groups = data.allow_all_groups;
    network.acl_enabled = data.acl_enabled;
    network.acl_default_allow = data.acl_default_allow;
    network.allowed_ips_from_acl = data.allowed_ips_from_acl;
    network.service_location_mode = data.service_location_mode;
    network.mfa_enabled = data.mfa_enabled;

    network.save(&mut *transaction).await?;
    network
        .set_allowed_groups(&mut transaction, &data.allowed_groups)
        .await?;
    // `None` keeps the overrides; `Some` replaces them.
    let group_mtus_before = network.fetch_group_client_mtus(&mut *transaction).await?;
    let group_mtus_after = if let Some(overrides) = &data.group_client_mtus {
        save_group_client_mtus(&network, &mut transaction, overrides).await?;
        network.fetch_group_client_mtus(&mut *transaction).await?
    } else {
        group_mtus_before.clone()
    };

    // Flow order is significant, but group order is not, so normalize group IDs before comparing.
    let current_mfa_assignments = normalize_mfa_flow_assignments(
        MfaFlow::for_location(&mut *transaction, network.id)
            .await?
            .into_iter()
            .map(|assignment| LocationMfaFlowAssignment {
                flow_id: assignment.id,
                is_default: assignment.is_default,
                group_ids: assignment.group_ids,
            })
            .collect(),
    );
    let mfa_assignments = normalize_mfa_flow_assignments(data.mfa_flows.clone());
    let mfa_assignments_changed = current_mfa_assignments != mfa_assignments;
    let mfa_assignments_updated = if mfa_assignments_changed {
        match MfaFlow::validate_mfa_flow_assignments_license(
            &mut transaction,
            &mfa_assignments,
            true,
            true,
        )
        .await
        {
            Ok(()) => true,
            Err(MfaFlowAssignmentLicenseError::Database(error)) => return Err(error.into()),
            Err(error) => return assignment_license_error_response(error),
        }
    } else {
        false
    };

    if mfa_assignments_updated {
        if let Err(error) =
            MfaFlow::assign_to_location(&mut transaction, network.id, &mfa_assignments).await
        {
            return assignment_error_response(&data.mfa_flows, error);
        }
    } else if let Some(response) =
        validate_mfa_flows_exist(&mut transaction, data.mfa_enabled, Some(network.id)).await?
    {
        return Ok(response);
    }

    // Posture policies: only when the request names them.
    let postures_assigned = if let Some(requested) = data.posture_checks.as_deref() {
        let requested = match validate_posture_assignment(&mut transaction, requested).await? {
            Ok(ids) => ids,
            Err(response) => return Ok(response),
        };
        let current = LocationPostures::find(&mut *transaction, network.id).await?;
        if current == requested {
            None
        } else {
            LocationPostures::set(&mut transaction, network.id, &requested).await?;
            Some(requested)
        }
    } else {
        None
    };
    if network.service_location_mode != ServiceLocationMode::Disabled
        && !LocationPostures::find(&mut *transaction, network.id)
            .await?
            .is_empty()
    {
        return Err(WebError::BadRequest(
            "Service location mode cannot be combined with posture policies".into(),
        ));
    }

    // `NetworkModified` sends the complete peer list. The gateway compares the peer count and
    // public keys, then replaces its peers, so separate device events are not needed.
    let mut events = Vec::new();
    sync_location_allowed_devices(&network, &mut transaction, None, &mut events).await?;

    let peers = get_location_allowed_peers(&network, &mut transaction).await?;
    let gateway_command = GatewayCommand::NetworkModified(network.clone(), peers);

    // commit DB transaction
    transaction.commit().await?;
    appstate.send_gateway_command(gateway_command);

    info!(
        "User {} updated WireGuard network {network_id}",
        session.user.username,
    );
    if let Some(posture_ids) = postures_assigned {
        crate::posture::worker::policies_changed([network.id]);
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationPosturesAssigned {
                location_id: network.id,
                location_name: network.name.clone(),
                posture_ids,
            }),
        })?;
    }
    if mfa_assignments_updated {
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationMfaFlowsAssigned {
                location_id: network.id,
                location_name: network.name.clone(),
                assignments: LocationMfaFlowAssignment::snapshot(&mfa_assignments),
            }),
        })?;
    }
    if group_mtus_before != group_mtus_after {
        appstate.emit_event(ApiEvent {
            context: context.clone(),
            event: Box::new(ApiEventType::LocationGroupMtusChanged {
                location_id: network.id,
                location_name: network.name.clone(),
                before: group_mtus_before,
                after: group_mtus_after,
            }),
        })?;
    }
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::VpnLocationModified {
            before,
            after: network.clone(),
        }),
    })?;
    Ok(ApiResponse::json(network, StatusCode::OK))
}

/// Delete a network
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/network/{network_id}",
    tag = "network",
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
    ),
    responses(
        (status = 200, description = "Network deleted."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 404, description = "Network not found.", body = ApiErrorResponse, example = json!({"msg": "network not found"})),
        (status = 500, description = "Unable to delete network.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn delete_network(
    _role: AdminRole,
    Path(network_id): Path<Id>,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
) -> ApiResult {
    debug!(
        "User {} deleting WireGuard network {network_id}",
        session.user.username,
    );
    let network = find_network(network_id, &appstate.pool).await?;
    let network_name = network.name.clone();
    let mut transaction = appstate.pool.begin().await?;
    let network_devices = network
        .get_devices_by_type(&mut *transaction, DeviceType::Network)
        .await?;
    for device in network_devices {
        device.delete(&mut *transaction).await?;
    }
    network.clone().delete(&mut *transaction).await?;
    transaction.commit().await?;
    appstate.send_gateway_command(GatewayCommand::NetworkDeleted(network_id, network_name));
    info!(
        "User {} deleted WireGuard network {network_id}",
        session.user.username,
    );
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::VpnLocationRemoved { location: network }),
    })?;

    Ok(ApiResponse::default())
}

/// List networks
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network",
    tag = "network",
    responses(
        (status = 200, description = "All networks.", body = [WireguardNetworkInfo]),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 500, description = "Unable to list networks.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn list_networks(_role: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    debug!("Listing WireGuard networks");
    let mut network_info = Vec::new();
    let networks = WireguardNetwork::all(&appstate.pool).await?;
    let mut postures = LocationPostures::all_by_location(&appstate.pool).await?;

    for network in networks {
        let allowed_groups = network.fetch_allowed_groups(&appstate.pool).await?;
        let gateways = GatewayInfo::find_by_location_id(&appstate.pool, network.id).await?;
        let has_devices =
            WireguardNetworkDevice::has_devices_in_network(&appstate.pool, network.id).await?;
        let group_client_mtus = network.fetch_group_client_mtus(&appstate.pool).await?;
        let posture_checks = postures.remove(&network.id).unwrap_or_default();
        network_info.push(WireguardNetworkInfo {
            network,
            gateways,
            allowed_groups,
            has_devices,
            posture_checks,
            group_client_mtus,
        });
    }
    network_info.sort_by(|a, b| a.network.name.cmp(&b.network.name));

    debug!("Listed WireGuard networks");

    Ok(ApiResponse::json(network_info, StatusCode::OK))
}

/// Count networks
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network/count",
    tag = "network",
    responses(
        (status = 200, description = "Number of networks.", body = LocationsCount),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 500, description = "Unable to count networks.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub async fn count_networks(_role: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    debug!("Counting WireGuard networks");
    let count = WireguardNetwork::count(&appstate.pool).await?;
    Ok(ApiResponse::json(
        LocationsCount {
            count: count as usize,
        },
        StatusCode::OK,
    ))
}

/// Get a network
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network/{network_id}",
    tag = "network",
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
    ),
    responses(
        (status = 200, description = "Network details.", body = WireguardNetworkInfo),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "access denied"})),
        (status = 404, description = "Network not found."),
        (status = 500, description = "Unable to get network.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn network_details(
    Path(network_id): Path<Id>,
    _role: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    debug!("Displaying network details for network {network_id}");
    let network = WireguardNetwork::find_by_id(&appstate.pool, network_id).await?;

    let response = match network {
        Some(network) => {
            let allowed_groups = network.fetch_allowed_groups(&appstate.pool).await?;
            let gateways = GatewayInfo::find_by_location_id(&appstate.pool, network_id).await?;
            let has_devices =
                WireguardNetworkDevice::has_devices_in_network(&appstate.pool, network_id).await?;
            let group_client_mtus = network.fetch_group_client_mtus(&appstate.pool).await?;
            let posture_checks = LocationPostures::find(&appstate.pool, network_id).await?;
            let network_info = WireguardNetworkInfo {
                network,
                gateways,
                allowed_groups,
                has_devices,
                posture_checks,
                group_client_mtus,
            };
            ApiResponse::json(network_info, StatusCode::OK)
        }
        None => ApiResponse::new(Value::Null, StatusCode::NOT_FOUND),
    };
    debug!("Displayed network details for network {network_id}");

    Ok(response)
}

/// Get the state of gateways in a location
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network/{network_id}/gateways",
    tag = "gateway",
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
    ),
    responses(
        (status = 200, description = "Gateway status in the location.", body = [GatewayInfo]),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Network not found.", body = ApiErrorResponse, example = json!({"msg": "network not found"})),
        (status = 500, description = "Unable to get gateway status.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn gateway_status(
    Path(network_id): Path<Id>,
    _role: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    debug!("Displaying gateway status for network {network_id}");

    let gateways = GatewayInfo::find_by_location_id(&appstate.pool, network_id).await?;

    debug!("Displayed gateway status for network {network_id}");

    Ok(ApiResponse::json(gateways, StatusCode::OK))
}

/// Get the state of gateways in all locations
///
/// Each entry carries the ID of the location the gateway belongs to.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network/gateways",
    tag = "gateway",
    responses(
        (status = 200, description = "Gateway status in all locations.", body = [GatewayInfo]),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to get gateway status.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn all_gateways_status(
    _role: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    debug!("Displaying gateways status for all networks.");

    let gateways = GatewayInfo::list(&appstate.pool).await?;

    Ok(ApiResponse::json(gateways, StatusCode::OK))
}

/// Import a network from a WireGuard configuration file
///
/// Devices found in the configuration are returned unmapped; use
/// `POST /api/v1/network/{network_id}/devices` to assign them to users.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/network/import",
    tag = "network",
    request_body = ImportNetworkData,
    responses(
        (status = 201, description = "Network imported.", body = ImportedNetworkData),
        (status = 400, description = "Invalid WireGuard configuration.", body = ApiErrorResponse, example = json!({"msg": "Invalid config file"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 413, description = "Configuration file too large.", body = ApiErrorResponse),
        (status = 500, description = "Unable to import network.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn import_network(
    _role: AdminRole,
    State(appstate): State<AppState>,
    context: ApiRequestContext,
    Json(data): Json<ImportNetworkData>,
) -> ApiResult {
    debug!("Importing network from config file");
    let (mut network, imported_devices) =
        parse_wireguard_config(&data.config).map_err(|error| {
            error!("{error}");
            WebError::Http(StatusCode::UNPROCESSABLE_ENTITY)
        })?;
    network.name = data.name;
    network.endpoint = data.endpoint;
    network.allow_all_groups = data.allow_all_groups;

    let mut transaction = appstate.pool.begin().await?;
    let network = network.save(&mut *transaction).await?;
    network
        .set_allowed_groups(&mut transaction, &data.allowed_groups)
        .await?;

    info!("New network {network} created");
    appstate.send_gateway_command(GatewayCommand::NetworkCreated(network.clone()));

    let reserved_ips = imported_devices
        .iter()
        .flat_map(|dev| dev.wireguard_ips.clone())
        .collect::<Vec<_>>();
    let (devices, gateway_events) =
        handle_imported_devices(&network, &mut transaction, imported_devices).await?;
    appstate.send_multiple_gateway_commands(gateway_events);

    // assign IPs for other existing devices
    debug!("Assigning IPs in imported network for remaining existing devices");
    let mut gateway_events = Vec::new();
    sync_location_allowed_devices(
        &network,
        &mut transaction,
        Some(&reserved_ips),
        &mut gateway_events,
    )
    .await?;
    appstate.send_multiple_gateway_commands(gateway_events);
    debug!("Assigned IPs in imported network for remaining existing devices");

    transaction.commit().await?;

    info!("Imported network {network} with {} devices", devices.len());
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::VpnLocationAdded {
            location: network.clone(),
        }),
    })?;

    Ok(ApiResponse::json(
        ImportedNetworkData { network, devices },
        StatusCode::CREATED,
    ))
}

// This is used exclusively for the wizard to map imported devices to users.
/// Assign imported devices to users
///
/// Used to finish the network import started with `POST /api/v1/network/import`.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/network/{network_id}/devices",
    tag = "network",
    request_body = MappedDevices,
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
    ),
    responses(
        (status = 201, description = "Devices assigned to users."),
        (status = 204, description = "Empty device list, nothing was assigned."),
        (status = 400, description = "Invalid device data.", body = ApiErrorResponse, example = json!({"msg": "Public key invalid"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Network not found.", body = ApiErrorResponse, example = json!({"msg": "network not found"})),
        (status = 500, description = "Unable to assign devices.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn add_user_devices(
    _role: AdminRole,
    session: SessionInfo,
    State(appstate): State<AppState>,
    Path(network_id): Path<Id>,
    Json(request_data): Json<MappedDevices>,
) -> ApiResult {
    let mapped_devices = request_data.devices;
    let user = session.user;
    let device_count = mapped_devices.len();

    debug!(
        "User {} mapping {device_count} devices for network {network_id}",
        user.username,
    );

    // finish early if no devices were provided in request
    if mapped_devices.is_empty() {
        debug!("No devices provided in request, skipping mapping");
        return Ok(ApiResponse::with_status(StatusCode::NO_CONTENT));
    }

    if let Some(network) = WireguardNetwork::find_by_id(&appstate.pool, network_id).await? {
        // wrap loop in transaction to abort if a device is invalid
        let mut transaction = appstate.pool.begin().await?;
        let events = handle_mapped_devices(&network, &mut transaction, &mapped_devices).await?;
        appstate.send_multiple_gateway_commands(events);
        transaction.commit().await?;

        info!(
            "User {} mapped {device_count} devices for {network_id} network",
            user.username,
        );

        Ok(ApiResponse::with_status(StatusCode::CREATED))
    } else {
        error!("Failed to map devices, network {network_id} not found");
        Err(WebError::ObjectNotFound(format!(
            "Network {network_id} not found"
        )))
    }
}

// assign IPs and generate configs for each network
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct AddDeviceResult {
    configs: Vec<DeviceConfig>,
    device: Device<Id>,
}

/// Add a device for a user
///
/// The device is added to every location. `wireguard_pubkey` has to be unique. Devices of
/// disabled users can only be added by an admin.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/device/{device_id}",
    tag = "device",
    params(
        ("device_id" = String, description = "Name of the user the device is created for.")
    ),
    request_body(content = AddDevice, example = json!({"name": "work laptop", "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="})),
    responses(
        (status = 201, description = "Device added.", body = AddDeviceResult, example = json!(
            {
                "configs": [
                    {
                        "network_id": 0,
                        "network_name": "network_name",
                        "config": "config",
                        "address": "0.0.0.0:8000",
                        "endpoint": "endpoint",
                        "allowed_ips": ["0.0.0.0:8000"],
                        "pubkey": "pubkey",
                        "dns": "8.8.8.8",
                        "keepalive_interval": 5,
                        "mfa_enabled": false,
                        "service_location_mode": "disabled"
                    }
                ],
                "device": {
                    "id": 1,
                    "name": "work laptop",
                    "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    "user_id": 1,
                    "created": "2024-07-10T10:25:43.231",
                    "device_type": "user",
                    "description": null,
                    "configured": true
                }
            }
        )),
        (status = 400, description = "No networks are configured, or a device with this public key already exists.", body = ApiErrorResponse, example = json!({"msg": "Failed to add device <name>, identical pubkey (<pubkey>) already exists"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "User not found.", body = ApiErrorResponse, example = json!({"msg": "user <username> not found"})),
        (status = 500, description = "Unable to add device.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn add_device(
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    // Alias, because otherwise `axum` reports conflicting routes.
    Path(username): Path<String>,
    Json(add_device): Json<AddDevice>,
) -> ApiResult {
    let device_name = add_device.name.clone();
    debug!(
        "User {} adding device {device_name} for user {username}",
        session.user.username,
    );

    let user = user_for_admin_or_self(&appstate.pool, &session, &username).await?;
    // Adding a device here means supplying its WireGuard key: manual configuration.
    ensure_may_manage_devices(&appstate.pool, &session).await?;
    ensure_may_configure_manually(&appstate.pool, &session).await?;

    // Disabled users' devices never get network access (see
    // `is_device_allowed_in_network`), and get stripped on the next sync even if
    // briefly assigned.
    if !user.is_active {
        warn!(
            "User {} tried to add a device for a disabled user {username}",
            session.user.username
        );

        return Err(WebError::Forbidden("User is disabled"));
    }

    let networks = WireguardNetwork::all(&appstate.pool).await?;
    if networks.is_empty() {
        error!("Failed to add device {device_name}, no networks found");
        return Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST));
    }

    Device::validate_pubkey(&add_device.wireguard_pubkey).map_err(WebError::PubkeyValidation)?;

    // Make sure there is no device with the same pubkey, such state may lead to unexpected issues
    if Device::find_by_pubkey(&appstate.pool, &add_device.wireguard_pubkey)
        .await?
        .is_some()
    {
        return Err(WebError::PubkeyExists(format!(
            "Failed to add device {device_name}, identical pubkey ({}) already exists",
            add_device.wireguard_pubkey
        )));
    }

    // save the device
    let mut transaction = appstate.pool.begin().await?;
    let device = Device::new(
        add_device.name,
        add_device.wireguard_pubkey,
        user.id,
        DeviceType::User,
        None,
        true,
    )
    .save(&mut *transaction)
    .await?;

    let (network_info, configs) =
        join_device_to_all_networks(&mut transaction, &device, &user).await?;

    // add peer on relevant gateways
    let events = vec![GatewayCommand::DeviceCreated(DeviceInfo {
        device: device.clone(),
        network_info: network_info.clone(),
    })];

    appstate.send_multiple_gateway_commands(events);

    let template_locations = configs
        .iter()
        .map(|c| TemplateLocation {
            name: c.network_name.clone(),
            assigned_ips: c.address.as_csv(),
        })
        .collect::<Vec<_>>();

    // hide session info if triggered by admin for other user
    let (session_ip, session_device_info) = if session.is_admin && session.user != user {
        (None, None)
    } else {
        (
            Some(session.session.ip_address.as_str()),
            session.session.device_info.clone(),
        )
    };
    new_device_added_mail(
        &user.email,
        &mut transaction,
        &device.name,
        &device.wireguard_pubkey,
        &template_locations,
        session_ip,
        session_device_info.as_deref(),
    )
    .await?;

    transaction.commit().await?;

    info!(
        "User {} added device {device_name} for user {username}",
        session.user.username
    );

    let result = AddDeviceResult {
        configs,
        device: device.clone(),
    };

    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::UserDeviceAdded {
            device,
            owner: user,
        }),
    })?;

    Ok(ApiResponse::json(result, StatusCode::CREATED))
}

/// Update a device
///
/// `wireguard_pubkey` has to be different from the public key of the location.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/device/{device_id}",
    tag = "device",
    params(
        ("device_id" = i64, description = "ID of the device.")
    ),
    request_body = ModifyDevice,
    responses(
        (status = 200, description = "Device updated.", body = Device, example = json!(
            {
                "id": 1,
                "name": "work laptop",
                "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "user_id": 1,
                "created": "2024-07-10T10:25:43.231",
                "device_type": "user",
                "description": null,
                "configured": true
            }
        )),
        (status = 400, description = "No networks are configured, or the public key belongs to a location.", body = ApiErrorResponse, example = json!({"msg": "device's pubkey must be different from server's pubkey"})),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Device not found.", body = ApiErrorResponse, example = json!({"msg": "device id <id> not found"})),
        (status = 500, description = "Unable to update device.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn modify_device(
    session: SessionInfo,
    context: ApiRequestContext,
    Path(device_id): Path<Id>,
    State(appstate): State<AppState>,
    Json(data): Json<ModifyDevice>,
) -> ApiResult {
    debug!("User {} updating device {device_id}", session.user.username);

    let mut device = device_for_admin_or_self(&appstate.pool, &session, device_id).await?;
    let before = device.clone();
    let client_settings = ensure_may_manage_devices(&appstate.pool, &session).await?;
    // A device set up by the client keeps its key; only the name may change.
    if !client_settings.may_configure_manually(session.is_admin)
        && (data.wireguard_pubkey != before.wireguard_pubkey
            || data.description != before.description)
    {
        warn!(
            "User {} tried to change the key or description of device {device_id}, but devices \
            can only be set up through the XGuard client",
            session.user.username
        );
        return Err(WebError::Forbidden(ONLY_CLIENT_ACTIVATION_MSG));
    }

    let networks = WireguardNetwork::all(&appstate.pool).await?;

    if networks.is_empty() {
        error!("Failed to update device {device_id}, no networks found");
        return Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST));
    }

    // check pubkeys
    for network in &networks {
        if network.pubkey == data.wireguard_pubkey {
            error!(
                "Failed to update device {device_id}, device's pubkey must be different from server's pubkey"
            );
            return Ok(ApiResponse::new(
                json!({"msg": "device's pubkey must be different from server's pubkey"}),
                StatusCode::BAD_REQUEST,
            ));
        }
    }

    // update device info
    device.update_from(data);

    // clone to use later

    device.save(&appstate.pool).await?;

    // send update to gateway's
    let mut network_info = Vec::new();
    for network in &networks {
        let wireguard_network_device =
            WireguardNetworkDevice::find(&appstate.pool, device.id, network.id).await?;
        if let Some(wireguard_network_device) = wireguard_network_device {
            let device_network_info = wireguard_network_device
                .to_device_network_info_runtime(&appstate.pool, network)
                .await?;
            network_info.push(device_network_info);
        }
    }
    appstate.send_gateway_command(GatewayCommand::DeviceModified(DeviceInfo {
        device: device.clone(),
        network_info,
    }));

    info!("User {} updated device {device_id}", session.user.username);

    let owner = device.get_owner(&appstate.pool).await?;
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::UserDeviceModified {
            owner,
            before,
            after: device.clone(),
        }),
    })?;

    Ok(ApiResponse::json(device, StatusCode::OK))
}

/// Get a device
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device/{device_id}",
    tag = "device",
    params(
        ("device_id" = i64, description = "ID of the device.")
    ),
    responses(
        (status = 200, description = "Device details.", body = Device, example = json!(
            {
                "id": 1,
                "name": "work laptop",
                "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "user_id": 1,
                "created": "2024-07-10T10:25:43.231",
                "device_type": "user",
                "description": null,
                "configured": true
            }
        )),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 404, description = "Device not found.", body = ApiErrorResponse, example = json!({"msg": "device id <id> not found"})),
        (status = 500, description = "Unable to get device.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn get_device(
    session: SessionInfo,
    Path(device_id): Path<Id>,
    State(appstate): State<AppState>,
) -> ApiResult {
    debug!("Retrieving device with id: {device_id}");
    let device = device_for_admin_or_self(&appstate.pool, &session, device_id).await?;
    debug!("Retrieved device with id: {device_id}");
    Ok(ApiResponse::json(device, StatusCode::OK))
}

/// Delete a device
///
/// The device is removed from every location and the gateways are updated.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/device/{device_id}",
    tag = "device",
    params(
        ("device_id" = i64, description = "ID of the device.")
    ),
    responses(
        (status = 200, description = "Device deleted."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Device not found.", body = ApiErrorResponse, example = json!({"msg": "device id <id> not found"})),
        (status = 500, description = "Unable to delete device.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn delete_device(
    session: SessionInfo,
    context: ApiRequestContext,
    Path(device_id): Path<Id>,
    State(appstate): State<AppState>,
) -> ApiResult {
    // bind username to a variable for easier reference
    let username = &session.user.username;

    debug!("User {username} deleting device {device_id}");
    let mut transaction = appstate.pool.begin().await?;

    let device = device_for_admin_or_self(&mut *transaction, &session, device_id).await?;
    ensure_may_manage_devices(&mut *transaction, &session).await?;

    let mut events = Vec::new();

    // prepare device info
    let device_info = DeviceInfo::from_device(&mut *transaction, device.clone()).await?;

    device.clone().delete(&mut *transaction).await?;

    let device_id = device_info.device.id;
    events.push(GatewayCommand::DeviceDeleted(device_info.clone()));

    // send generated gateway commands
    appstate.send_multiple_gateway_commands(events);

    // Emit event specific to the device type.
    match device.device_type {
        DeviceType::User => {
            let owner = device_info.device.get_owner(&mut *transaction).await?;
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::UserDeviceRemoved { device, owner }),
            })?;
        }
        DeviceType::Network => {
            if let Some(network_info) = device_info.network_info.first() {
                let location =
                    WireguardNetwork::find_by_id(&mut *transaction, network_info.network_id)
                        .await?;
                if let Some(location) = location {
                    appstate.emit_event(ApiEvent {
                        context,
                        event: Box::new(ApiEventType::NetworkDeviceRemoved { device, location }),
                    })?;
                } else {
                    error!(
                        "Network device {}({}) is assigned to non-existent location {}",
                        device.name, device.id, network_info.network_id
                    );
                }
            } else {
                error!(
                    "Network device {}({}) has no network assigned",
                    device.name, device.id
                );
            }
        }
    }
    transaction.commit().await?;
    info!("User {username} deleted device {device_id}");

    Ok(ApiResponse::default())
}

/// List devices
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device",
    tag = "device",
    responses(
        (status = 200, description = "All devices.", body = [Device], example = json!([
            {
                "id": 1,
                "name": "work laptop",
                "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "user_id": 1,
                "created": "2024-07-10T10:25:43.231",
                "device_type": "user",
                "description": null,
                "configured": true
            }
        ])),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to list devices.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn list_devices(_role: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    debug!("Listing devices");
    let devices = Device::all(&appstate.pool).await?;
    info!("Listed {} devices", devices.len());

    Ok(ApiResponse::json(devices, StatusCode::OK))
}

/// List the devices of a user
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device/user/{username}",
    tag = "device",
    params(
        ("username" = String, description = "Name of the user.")
    ),
    responses(
        (status = 200, description = "All devices of the user.", body = [Device], example = json!([
            {
                "id": 1,
                "name": "work laptop",
                "wireguard_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "user_id": 1,
                "created": "2024-07-10T10:25:43.231",
                "device_type": "user",
                "description": null,
                "configured": true
            }
        ])),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "Admin access required"})),
        (status = 500, description = "Unable to list user devices.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"}))
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn list_user_devices(
    session: SessionInfo,
    State(appstate): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult {
    // only allow for admin or user themselves
    if !session.is_admin && session.user.username != username {
        warn!(
            "User {} tried to list devices for user {username}, but is not an admin",
            session.user.username
        );
        return Err(WebError::Forbidden("Admin access required"));
    }
    debug!("Listing devices for user: {username}");
    let devices = Device::all_for_username(&appstate.pool, &username).await?;
    info!("Listed {} devices for user: {username}", devices.len());

    Ok(ApiResponse::json(devices, StatusCode::OK))
}

/// Get the WireGuard configuration of a device in a location
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/network/{network_id}/device/{device_id}/config",
    tag = "network",
    params(
        ("network_id" = i64, Path, description = "ID of the network."),
        ("device_id" = i64, Path, description = "ID of the device."),
    ),
    responses(
        (status = 200, description = "WireGuard configuration of the device.", body = String, example = json!("[Interface]\nPrivateKey = YOUR_PRIVATE_KEY\nAddress = 10.0.0.12\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/24\nEndpoint = vpn.example.com:50051\nPersistentKeepalive = 25")),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Network or device not found.", body = ApiErrorResponse, example = json!({"msg": "device not found"})),
        (status = 500, description = "Unable to get device configuration.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn download_config(
    session: SessionInfo,
    State(appstate): State<AppState>,
    Path((network_id, device_id)): Path<(Id, Id)>,
) -> Result<String, WebError> {
    debug!("Creating config for device {device_id} in network {network_id}");

    let network = find_network(network_id, &appstate.pool).await?;
    let device = device_for_admin_or_self(&appstate.pool, &session, device_id).await?;
    ensure_may_configure_manually(&appstate.pool, &session).await?;
    let user = User::find_by_id(&appstate.pool, device.user_id)
        .await?
        .ok_or(WebError::ObjectNotFound(format!(
            "User {} not found",
            device.user_id
        )))?;
    let wireguard_network_device =
        WireguardNetworkDevice::find(&appstate.pool, device_id, network_id).await?;
    if let Some(wireguard_network_device) = wireguard_network_device {
        info!("Created config for device {}({device_id})", device.name);
        let mut conn = appstate.pool.acquire().await?;
        let device_config =
            build_device_config(&mut conn, &network, &wireguard_network_device, &user).await?;
        Ok(device_config.config)
    } else {
        error!(
            "Failed to create config, no IP address found for device: {}({})",
            device.name, device.id
        );
        Err(WebError::ObjectNotFound(format!(
            "No IP address found for device: {}({})",
            device.name, device.id
        )))
    }
}

/// Get the WireGuard configuration of a user device
///
/// Returns one configuration per location the device is allowed to connect to.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/device/{device_id}/config",
    tag = "device",
    params(
        ("device_id" = i64, Path, description = "ID of the device."),
    ),
    responses(
        (status = 200, description = "Device configuration for each location.", body = [Object], example = json!([
            {"network_id": 1, "network_name": "office", "config": "[Interface]\n...", "mfa_enabled": false, "posture_check_required": false}
        ])),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges or the request must target your own account.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Device not found.", body = ApiErrorResponse, example = json!({"msg": "device not found"})),
        (status = 500, description = "Unable to get device configuration.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = [])
    )
))]
pub(crate) async fn user_device_configs(
    session: SessionInfo,
    State(appstate): State<AppState>,
    Path(device_id): Path<Id>,
) -> ApiResult {
    debug!("Creating WireGuard configs for user device {device_id}.");

    let device = device_for_admin_or_self(&appstate.pool, &session, device_id).await?;
    ensure_may_configure_manually(&appstate.pool, &session).await?;
    let user = User::find_by_id(&appstate.pool, device.user_id)
        .await?
        .ok_or(WebError::ObjectNotFound(format!(
            "User {} not found",
            device.user_id
        )))?;
    let locations = WireguardNetwork::find_user_device_networks(&appstate.pool, device_id).await?;
    let group_mtus = WireguardNetwork::group_client_mtus_for_user(&appstate.pool, user.id).await?;

    let mut result = Vec::new();
    for location in locations {
        let location_device = WireguardNetworkDevice::find(&appstate.pool, device_id, location.id)
            .await?
            .ok_or(WebError::ObjectNotFound(format!(
                "No IP address found for device: {}({})",
                device.name, device.id
            )))?;
        debug!(
            "Created WireGuard config for user device {device_id} in location {}.",
            location.name
        );
        let mut conn = appstate.pool.acquire().await?;
        let device_config = build_device_config_with_group_mtus(
            &mut conn,
            &location,
            &location_device,
            &user,
            &group_mtus,
        )
        .await?;
        result.push(DeviceWireGuardConfig {
            network_id: device_config.network_id,
            network_name: device_config.network_name,
            config: device_config.config,
            mfa_enabled: device_config.mfa_enabled,
            location_mfa_mode: device_config.location_mfa_mode,
            posture_check_required: device_config.posture_check_required,
        });
    }

    Ok(ApiResponse::json(result, StatusCode::OK))
}
