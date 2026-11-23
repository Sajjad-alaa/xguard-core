//! "Allowed IPs from firewall rules" in what desktop and mobile clients receive over the Edge
//! protocol: the enrollment response and polled configurations, whose revision changes when a
//! rule or a group membership changes the device's routes.

use std::time::Duration;

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use xguard_common::{
    db::{
        Id,
        models::{WireguardNetwork, group::Group},
    },
    firewall::{FirewallRule, FirewallRuleAction, FirewallRuleInput},
};
use xguard_proto::{
    client_types::{InstanceInfoRequest, InstanceInfoResponse, NewDevice},
    proxy::{CoreRequest, core_request, core_response},
};

use super::support::{
    assert_device_config_response, complete_proxy_handshake, create_enrollment_token,
    create_network, create_polling_token, create_user, create_user_with_device, make_device_info,
    start_enrollment_session,
};
use crate::{servers::polling::MIN_DEVICE_POLL_INTERVAL, tests::common::HandlerTestContext};

fn allow(name: &str, destinations: &[&str]) -> FirewallRuleInput {
    FirewallRuleInput {
        name: name.into(),
        description: String::new(),
        enabled: true,
        priority: 1000,
        action: FirewallRuleAction::Allow,
        all_locations: true,
        locations: Vec::new(),
        any_source: true,
        all_users: false,
        all_network_devices: false,
        users: Vec::new(),
        groups: Vec::new(),
        devices: Vec::new(),
        any_destination: false,
        destinations: destinations.iter().map(|d| (*d).to_string()).collect(),
        protocols: Vec::new(),
        ports: Vec::new(),
        expires_at: None,
    }
}

async fn create_rule(pool: &PgPool, rule: FirewallRuleInput) -> Id {
    let rule = rule.validate().unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let id = FirewallRule::create(&mut transaction, &rule).await.unwrap();
    transaction.commit().await.unwrap();
    id
}

/// A location (VPN network 10.0.0.0/24) that routes everything statically, with the firewall on.
async fn location(pool: &PgPool, from_rules: bool) -> WireguardNetwork<Id> {
    let mut network = create_network(pool).await;
    network.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
    network.acl_enabled = true;
    network.allowed_ips_from_acl = from_rules;
    network.save(pool).await.unwrap();
    network
}

#[sqlx::test]
async fn test_enrollment_sends_rule_derived_allowed_ips(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let derived = location(&context.pool, true).await;
    let static_list = location(&context.pool, false).await;
    create_rule(&context.pool, allow("intranet", &["192.168.60.0/24"])).await;

    let user = create_user(&context.pool).await;
    let token = create_enrollment_token(&context.pool, user.id, Some(user.id)).await;
    start_enrollment_session(&mut context, &token.id).await;
    context.mock_proxy().send_request(CoreRequest {
        id: 1,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::NewDevice(NewDevice {
            name: "Split tunnel".to_owned(),
            pubkey: "AA0aJzRBTltodYKPnKm2w9Dd6vcEER4rOEVSX2x5hpM=".to_owned(),
            token: Some(token.id.clone()),
        })),
    });
    let response = context.mock_proxy_mut().recv_outbound().await;
    let configs = assert_device_config_response(&response).configs.clone();

    let config = |id: Id| {
        configs
            .iter()
            .find(|config| config.network_id == id)
            .expect("config for the location")
            .clone()
    };
    let split = config(derived.id);
    assert_eq!(split.allowed_ips, "10.0.0.0/24,192.168.60.0/24");
    assert!(
        split
            .config
            .contains("AllowedIPs = 10.0.0.0/24,192.168.60.0/24\n"),
        "{}",
        split.config
    );
    assert_eq!(config(static_list.id).allowed_ips, "0.0.0.0/0");

    context.finish().await.expect_server_finished().await;
}

async fn poll(
    context: &mut HandlerTestContext,
    id: u64,
    token: &str,
    revision: Option<&str>,
) -> InstanceInfoResponse {
    tokio::time::sleep(MIN_DEVICE_POLL_INTERVAL + Duration::from_millis(50)).await;
    context.mock_proxy().send_request(CoreRequest {
        id,
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::InstanceInfo(InstanceInfoRequest {
            token: token.to_owned(),
            config_revision: revision.map(str::to_owned),
        })),
    });
    match context.mock_proxy_mut().recv_outbound().await.payload {
        Some(core_response::Payload::InstanceInfo(info)) => info,
        other => panic!(
            "expected InstanceInfo, got {:?}",
            other.as_ref().map(std::mem::discriminant)
        ),
    }
}

fn routes(info: &InstanceInfoResponse) -> String {
    info.device_config.as_ref().expect("device config").configs[0]
        .allowed_ips
        .clone()
}

#[sqlx::test]
async fn test_rule_and_group_changes_bump_the_polled_revision(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    location(&context.pool, true).await;
    let (user, device) = create_user_with_device(&context.pool).await;
    let token = create_polling_token(&context.pool, device.id).await;

    // No rule applies: only the VPN network is routed.
    let first = poll(&mut context, 1, &token, None).await;
    assert_eq!(routes(&first), "10.0.0.0/24");
    let revision = first.config_revision.clone().unwrap();

    // A rule for a group the user is not in changes nothing.
    let group = Group::new("engineering").save(&context.pool).await.unwrap();
    create_rule(
        &context.pool,
        FirewallRuleInput {
            any_source: false,
            groups: vec![group.id],
            ..allow("engineering", &["192.168.50.0/24"])
        },
    )
    .await;
    let unchanged = poll(&mut context, 2, &token, Some(&revision)).await;
    assert_eq!(unchanged.not_modified, Some(true));

    // Joining the group does: a new revision with the new route.
    user.add_to_group(&context.pool, &group).await.unwrap();
    let joined = poll(&mut context, 3, &token, Some(&revision)).await;
    assert_eq!(joined.not_modified, Some(false));
    assert_eq!(routes(&joined), "10.0.0.0/24,192.168.50.0/24");
    let joined_revision = joined.config_revision.clone().unwrap();
    assert_ne!(joined_revision, revision);

    // So does a rule change.
    let direct = create_rule(
        &context.pool,
        FirewallRuleInput {
            any_source: false,
            users: vec![user.id],
            ..allow("direct", &["192.168.51.0/24"])
        },
    )
    .await;
    let widened = poll(&mut context, 4, &token, Some(&joined_revision)).await;
    assert_eq!(widened.not_modified, Some(false));
    assert_eq!(routes(&widened), "10.0.0.0/24,192.168.50.0/23");

    // Removing it returns to the previous configuration and revision.
    FirewallRule::delete(&context.pool, direct).await.unwrap();
    let back = poll(&mut context, 5, &token, Some(&joined_revision)).await;
    assert_eq!(back.not_modified, Some(true));
    assert_eq!(
        back.config_revision.as_deref(),
        Some(joined_revision.as_str())
    );

    context.finish().await.expect_server_finished().await;
}
