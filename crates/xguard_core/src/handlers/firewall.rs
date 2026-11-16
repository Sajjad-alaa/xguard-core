//! Firewall rules API (admin only).
//!
//! Every change is audited and makes gateways re-check their policy; a gateway only receives a
//! new policy when its compiled revision actually changed.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde_json::json;
use xguard_common::{
    db::{Id, models::WireguardNetwork},
    firewall::{self, FirewallRule, FirewallRuleInput, SnatBinding, SnatBindingInput},
    gateway_event::GatewayCommand,
};

use super::{ApiResponse, ApiResult};
#[cfg(feature = "openapi")]
use crate::handlers::ApiErrorResponse;
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

async fn find_rule(appstate: &AppState, id: Id) -> Result<FirewallRule, WebError> {
    FirewallRule::find_by_id(&appstate.pool, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Firewall rule {id} not found")))
}

/// List firewall rules in evaluation order
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/firewall/rule",
    tag = "firewall",
    responses(
        (status = 200, description = "All firewall rules, in evaluation order.", body = [FirewallRule]),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn list_firewall_rules(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let rules = FirewallRule::all(&appstate.pool).await?;
    Ok(ApiResponse::json(rules, StatusCode::OK))
}

/// Get a firewall rule
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/firewall/rule/{id}",
    tag = "firewall",
    params(("id" = Id, Path, description = "Rule ID")),
    responses(
        (status = 200, description = "The rule.", body = FirewallRule),
        (status = 404, description = "No such rule.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn get_firewall_rule(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let rule = find_rule(&appstate, id).await?;
    Ok(ApiResponse::json(rule, StatusCode::OK))
}

/// Create a firewall rule
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/firewall/rule",
    tag = "firewall",
    request_body = FirewallRuleInput,
    responses(
        (status = 201, description = "Rule created.", body = FirewallRule),
        (status = 400, description = "Invalid rule.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn create_firewall_rule(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<FirewallRuleInput>,
) -> ApiResult {
    let input = input.validate()?;
    let mut transaction = appstate.pool.begin().await?;
    let id = FirewallRule::create(&mut transaction, &input).await?;
    transaction.commit().await?;
    let rule = find_rule(&appstate, id).await?;
    info!(
        "User {} added firewall rule {} ({id})",
        session.user.username, rule.name
    );
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::FirewallRuleAdded { rule: rule.clone() }),
    })?;
    Ok(ApiResponse::json(rule, StatusCode::CREATED))
}

/// Replace a firewall rule
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/firewall/rule/{id}",
    tag = "firewall",
    params(("id" = Id, Path, description = "Rule ID")),
    request_body = FirewallRuleInput,
    responses(
        (status = 200, description = "Rule updated.", body = FirewallRule),
        (status = 400, description = "Invalid rule.", body = ApiErrorResponse),
        (status = 404, description = "No such rule.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn update_firewall_rule(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(input): Json<FirewallRuleInput>,
) -> ApiResult {
    let input = input.validate()?;
    let before = find_rule(&appstate, id).await?;
    let mut transaction = appstate.pool.begin().await?;
    FirewallRule::update(&mut transaction, id, &input).await?;
    transaction.commit().await?;
    let after = find_rule(&appstate, id).await?;
    info!(
        "User {} modified firewall rule {} ({id})",
        session.user.username, after.name
    );
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::FirewallRuleModified {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Delete a firewall rule
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/firewall/rule/{id}",
    tag = "firewall",
    params(("id" = Id, Path, description = "Rule ID")),
    responses(
        (status = 200, description = "Rule deleted."),
        (status = 404, description = "No such rule.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn delete_firewall_rule(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let rule = find_rule(&appstate, id).await?;
    FirewallRule::delete(&appstate.pool, id).await?;
    info!(
        "User {} removed firewall rule {} ({id})",
        session.user.username, rule.name
    );
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::FirewallRuleRemoved { rule }),
    })?;
    Ok(ApiResponse::with_status(StatusCode::OK))
}

/// Show the policy a location's gateways enforce
///
/// The compiled form of the rules: which rules apply at the location, in order, and how many
/// addresses each one covers. Useful to check a change before relying on it.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/firewall/location/{id}/policy",
    tag = "firewall",
    params(("id" = Id, Path, description = "Location ID")),
    responses(
        (status = 200, description = "Compiled policy, or null when the location has none."),
        (status = 404, description = "No such location.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn location_firewall_policy(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let mut conn = appstate.pool.acquire().await?;
    let location = WireguardNetwork::find_by_id(&mut *conn, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("Location {id} not found")))?;
    let Some(policy) = firewall::compile(&mut conn, &location).await? else {
        return Ok(ApiResponse::json(json!(null), StatusCode::OK));
    };
    let set_size = |set: Option<u32>| set.map(|s| policy.sets[s as usize].len());
    let rules: Vec<_> = policy
        .rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "action": rule.action,
                "source_ranges": set_size(rule.source),
                "destination_ranges": set_size(rule.destination),
                "protocols": rule.protocols,
                "ports": rule.ports.iter().map(|p| format!("{}-{}", p.start(), p.end())).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(ApiResponse::json(
        json!({
            "revision": policy.revision,
            "default_action": policy.default_action,
            "rules": rules,
            "snat_bindings": policy.snat.len(),
        }),
        StatusCode::OK,
    ))
}

/// Body of a SNAT binding update.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SnatPublicIp {
    pub public_ip: String,
}

/// List SNAT bindings
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/v1/firewall/snat",
    tag = "firewall",
    responses((status = 200, description = "All SNAT bindings.", body = [SnatBinding])),
    security(("cookie" = []))
))]
pub async fn list_snat_bindings(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let bindings = SnatBinding::all(&appstate.pool).await?;
    Ok(ApiResponse::json(bindings, StatusCode::OK))
}

/// Add a SNAT binding
///
/// Traffic from the user's devices at the location leaves the gateway with `public_ip`.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/v1/firewall/snat",
    tag = "firewall",
    request_body = SnatBindingInput,
    responses(
        (status = 201, description = "Binding created.", body = SnatBinding),
        (status = 400, description = "Invalid or duplicate binding.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn create_snat_binding(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(input): Json<SnatBindingInput>,
) -> ApiResult {
    let binding = SnatBinding::create(&appstate.pool, &input).await?;
    info!(
        "User {} added SNAT to {} for user {} at location {}",
        session.user.username, binding.public_ip, binding.user_id, binding.location_id
    );
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::UserSnatBindingAdded {
            binding: binding.clone(),
        }),
    })?;
    Ok(ApiResponse::json(binding, StatusCode::CREATED))
}

/// Change a SNAT binding's public address
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/api/v1/firewall/snat/{id}",
    tag = "firewall",
    params(("id" = Id, Path, description = "Binding ID")),
    request_body = SnatPublicIp,
    responses(
        (status = 200, description = "Binding updated.", body = SnatBinding),
        (status = 400, description = "Invalid address.", body = ApiErrorResponse),
        (status = 404, description = "No such binding.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn update_snat_binding(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(body): Json<SnatPublicIp>,
) -> ApiResult {
    let before = SnatBinding::find_by_id(&appstate.pool, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("SNAT binding {id} not found")))?;
    let after = SnatBinding::set_public_ip(&appstate.pool, id, &body.public_ip).await?;
    info!(
        "User {} changed SNAT binding {id} to {}",
        session.user.username, after.public_ip
    );
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::UserSnatBindingModified {
            before,
            after: after.clone(),
        }),
    })?;
    Ok(ApiResponse::json(after, StatusCode::OK))
}

/// Delete a SNAT binding
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/api/v1/firewall/snat/{id}",
    tag = "firewall",
    params(("id" = Id, Path, description = "Binding ID")),
    responses(
        (status = 200, description = "Binding deleted."),
        (status = 404, description = "No such binding.", body = ApiErrorResponse),
    ),
    security(("cookie" = []))
))]
pub async fn delete_snat_binding(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    let binding = SnatBinding::find_by_id(&appstate.pool, id)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound(format!("SNAT binding {id} not found")))?;
    SnatBinding::delete(&appstate.pool, id).await?;
    info!("User {} removed SNAT binding {id}", session.user.username);
    appstate.send_gateway_command(GatewayCommand::FirewallRulesChanged);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::UserSnatBindingRemoved { binding }),
    })?;
    Ok(ApiResponse::with_status(StatusCode::OK))
}
