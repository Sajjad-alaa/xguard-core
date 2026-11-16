use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::{mpsc::unbounded_channel, watch};
use tonic::{Code, Status};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, DeviceType, User,
            device::{DeviceInfo, DeviceNetworkInfo, WireguardNetworkDevice},
            gateway::Gateway,
            vpn_client_session::VpnClientSession,
            wireguard::{ServiceLocationMode, WireguardNetwork},
        },
        setup_pool,
    },
    gateway_event::GatewayCommand,
    gateway_types::WireguardPeer,
    secret::SecretStringWrapper,
};
use xguard_proto::gateway::{Configuration, PeerStats, core_response};

use super::{GatewayHandler, is_gateway_already_connected, try_protos_into_stats_message};
use crate::updates::GatewayUpdatesHandler;

#[test]
fn test_gateway_already_connected_requires_exact_status() {
    assert!(is_gateway_already_connected(&Status::new(
        Code::Internal,
        "Client already connected",
    )));
    assert!(!is_gateway_already_connected(&Status::new(
        Code::Internal,
        "client already connected",
    )));
    assert!(!is_gateway_already_connected(&Status::new(
        Code::AlreadyExists,
        "Client already connected",
    )));
}

fn test_network(mfa_enabled: bool) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        "test-network".into(),
        51820,
        "127.0.0.1".into(),
        None,
        Vec::new(),
        true,
        false,
        false,
        false,
        mfa_enabled,
        ServiceLocationMode::Disabled,
    )
    .with_id(1)
}

fn build_peer_stats(endpoint: &str) -> PeerStats {
    PeerStats {
        public_key: "peer-public-key".to_owned(),
        endpoint: endpoint.to_owned(),
        upload: 123,
        download: 456,
        keepalive_interval: 25,
        latest_handshake: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        allowed_ips: "10.10.0.2/32".to_owned(),
    }
}

fn build_network() -> WireguardNetwork<Id> {
    let mut network = WireguardNetwork::new(
        "test-network".to_owned(),
        51820,
        "198.51.100.10".to_owned(),
        Some("1.1.1.1".to_owned()),
        ["0.0.0.0/0".parse().expect("valid allowed IP network")],
        false,
        false,
        false,
        false,
        false, // mfa_enabled
        ServiceLocationMode::default(),
    )
    .set_address([
        "10.10.0.1/24".parse().expect("valid IPv4 network"),
        "fd00::1/64".parse().expect("valid IPv6 network"),
    ])
    .expect("valid network addresses")
    .with_id(1);
    network.pubkey = "network-public-key".to_owned();
    network.prvkey = "network-private-key".to_owned();
    network.mtu = 1420;
    network.fwmark = 4321;
    network.keepalive_interval = 25;
    network.peer_disconnect_threshold = 180;
    network
}

#[test]
fn try_protos_into_stats_message_maps_valid_peer_stats() {
    let stats = try_protos_into_stats_message(build_peer_stats("203.0.113.10:51820"), 11, 22)
        .expect("valid peer stats should be converted");

    assert_eq!(stats.location_id, 11);
    assert_eq!(stats.gateway_id, 22);
    assert_eq!(stats.device_pubkey, "peer-public-key");
    assert_eq!(stats.endpoint.to_string(), "203.0.113.10:51820");
    assert_eq!(stats.upload, 123);
    assert_eq!(stats.download, 456);
    assert_eq!(
        stats.latest_handshake,
        DateTime::from_timestamp(1_700_000_000, 0)
            .expect("valid handshake timestamp")
            .naive_utc()
    );
}

#[test]
fn try_protos_into_stats_message_rejects_invalid_endpoint() {
    let stats = try_protos_into_stats_message(build_peer_stats("not-a-socket-address"), 11, 22);

    assert!(stats.is_none());
}

#[test]
fn try_protos_into_stats_message_returns_none_for_missing_handshake() {
    let stats = try_protos_into_stats_message(
        PeerStats {
            latest_handshake: None,
            ..build_peer_stats("203.0.113.10:51820")
        },
        11,
        22,
    );

    assert!(stats.is_none());
}

#[test]
fn try_protos_into_stats_message_returns_none_for_invalid_timestamp() {
    let stats = try_protos_into_stats_message(
        PeerStats {
            latest_handshake: Some(Timestamp {
                seconds: i64::MAX,
                nanos: 0,
            }),
            ..build_peer_stats("203.0.113.10:51820")
        },
        11,
        22,
    );

    assert!(stats.is_none());
}

#[test]
fn gen_config_maps_network_fields() {
    let config = Configuration::new(
        &build_network(),
        vec![WireguardPeer {
            pubkey: "peer-public-key".to_owned(),
            allowed_ips: vec!["10.10.0.2/32".to_owned()],
            preshared_key: Some("peer-preshared-key".to_owned().into()),
            keepalive_interval: Some(25),
        }],
    );

    assert_eq!(config.name, "test-network");
    assert_eq!(config.port, 51820);
    assert_eq!(config.private_key, "network-private-key");
    assert_eq!(config.addresses, ["10.10.0.1/24", "fd00::1/64"]);
    assert_eq!(config.mtu, 1420);
    assert_eq!(config.fwmark, 4321);

    let peer = config
        .peers
        .first()
        .expect("generated config should include peer");
    assert_eq!(peer.pubkey, "peer-public-key");
    assert_eq!(peer.allowed_ips, ["10.10.0.2/32"]);
    assert_eq!(peer.preshared_key.as_deref(), Some("peer-preshared-key"));
    assert_eq!(peer.keepalive_interval, Some(25));
}

#[test]
fn gen_config_preserves_empty_peers() {
    let config = Configuration::new(&build_network(), Vec::new());

    assert_eq!(config.peers, [] as [xguard_proto::gateway::Peer; 0]);
}

fn test_handler<'a>(mfa_enabled: bool) -> GatewayUpdatesHandler<'a> {
    let network = test_network(mfa_enabled);
    let (tx, _rx) = unbounded_channel();

    GatewayUpdatesHandler::new(network, "gateway", None, tx)
}

#[test]
fn test_device_modified_debug_redacts_network_preshared_key() {
    let device = Device::new(
        "test-device".to_owned(),
        "test-pubkey".to_owned(),
        1,
        DeviceType::User,
        None,
        true,
    )
    .with_id(1);
    let command = GatewayCommand::DeviceModified(DeviceInfo {
        device,
        network_info: vec![DeviceNetworkInfo {
            network_id: 1,
            device_wireguard_ips: Vec::new(),
            preshared_key: Some(SecretStringWrapper::from("device-modified-secret")),
            is_authorized: true,
        }],
    });

    let debug = format!("{command:?}");
    assert!(!debug.contains("device-modified-secret"));
    assert!(debug.contains("preshared_key: Some("));
}

#[test]
fn test_runtime_peer_update_strips_preshared_key_for_non_mfa_locations() {
    let handler = test_handler(false);

    let peer = handler
        .runtime_peer_update(
            "device",
            "device-pubkey".into(),
            vec!["10.1.1.2".into()],
            true,
            Some("legacy-psk".into()),
        )
        .unwrap();

    assert_eq!(peer.pubkey, "device-pubkey");
    assert_eq!(peer.allowed_ips, ["10.1.1.2"]);
    assert_eq!(peer.preshared_key, None);
    assert_eq!(peer.keepalive_interval, Some(25));
}

#[test]
fn test_runtime_peer_update_skips_authorized_mfa_peer_without_session_preshared_key() {
    let handler = test_handler(true);

    let peer = handler.runtime_peer_update(
        "device",
        "device-pubkey".into(),
        vec!["10.1.1.2".into()],
        true,
        None,
    );

    assert_eq!(peer, None);
}

#[test]
fn test_runtime_peer_update_preserves_session_preshared_key_for_authorized_mfa_peer() {
    let handler = test_handler(true);

    let peer = handler
        .runtime_peer_update(
            "device",
            "device-pubkey".into(),
            vec!["10.1.1.2".into()],
            true,
            Some("session-psk".into()),
        )
        .unwrap();

    assert_eq!(peer.preshared_key, Some("session-psk".into()));
}

#[test]
fn test_runtime_peer_update_preserves_session_preshared_key_for_authorized_posture_peer() {
    let mut handler = test_handler(false);
    handler.set_session_authorization_required(true);

    let peer = handler
        .runtime_peer_update(
            "device",
            "device-pubkey".into(),
            vec!["10.1.1.2".into()],
            true,
            Some("session-psk".into()),
        )
        .unwrap();

    assert_eq!(peer.preshared_key, Some("session-psk".into()));
}

#[sqlx::test]
async fn test_send_configuration_includes_mfa_peers_with_session_preshared_key(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;

    let user = User::new(
        "testuser",
        Some("password123"),
        "Test",
        "User",
        "test@example.com",
        None,
    )
    .save(&pool)
    .await
    .unwrap();

    let new_device = Device::new(
        "device-new".into(),
        "pubkey-new".into(),
        user.id,
        DeviceType::User,
        None,
        true,
    )
    .save(&pool)
    .await
    .unwrap();

    let connected_device = Device::new(
        "device-connected".into(),
        "pubkey-connected".into(),
        user.id,
        DeviceType::User,
        None,
        true,
    )
    .save(&pool)
    .await
    .unwrap();

    let mut network = WireguardNetwork::default()
        .try_set_address("10.7.1.1/24")
        .unwrap();
    network.name = "mfa-full-config-location".to_owned();
    network.mfa_enabled = true;
    network.service_location_mode = ServiceLocationMode::Disabled;
    let network = network.save(&pool).await.unwrap();

    WireguardNetworkDevice::new(
        network.id,
        new_device.id,
        vec![IpAddr::from_str("10.7.1.2").unwrap()],
    )
    .insert(&pool)
    .await
    .unwrap();

    WireguardNetworkDevice::new(
        network.id,
        connected_device.id,
        vec![IpAddr::from_str("10.7.1.3").unwrap()],
    )
    .insert(&pool)
    .await
    .unwrap();

    let mut new_session = VpnClientSession::new(network.id, user.id, new_device.id, None, false);
    new_session.preshared_key = Some("new-session-psk".into());
    new_session.save(&pool).await.unwrap();

    let mut connected_session = VpnClientSession::new(
        network.id,
        user.id,
        connected_device.id,
        Some(Utc::now().naive_utc()),
        false,
    );
    connected_session.preshared_key = Some("connected-session-psk".into());
    connected_session.save(&pool).await.unwrap();

    let gateway = Gateway::new(network.id, "gateway", "127.0.0.1", 50051, "test")
        .save(&pool)
        .await
        .unwrap();
    let (connection_events_tx, _connection_events_rx) = unbounded_channel();
    let (peer_stats_tx, _peer_stats_rx) = unbounded_channel();
    let (_certs_tx, certs_rx) = watch::channel(Arc::new(HashMap::<Id, String>::new()));
    let handler = GatewayHandler::new(
        gateway,
        pool.clone(),
        unbounded_channel().1,
        connection_events_tx,
        peer_stats_tx,
        certs_rx,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let (tx, mut rx) = unbounded_channel();

    handler.send_configuration(&tx).await.unwrap();

    let response = rx.recv().await.unwrap();
    let Some(core_response::Payload::Config(configuration)) = response.payload else {
        panic!("expected gateway config payload");
    };

    assert_eq!(configuration.peers.len(), 2);
    assert_eq!(
        configuration
            .peers
            .iter()
            .map(|peer| (peer.pubkey.as_str(), peer.preshared_key.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("pubkey-new", Some("new-session-psk")),
            ("pubkey-connected", Some("connected-session-psk")),
        ]
    );
}

async fn firewall_location(pool: &sqlx::PgPool, acl_enabled: bool) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        "firewalled".into(),
        51820,
        "127.0.0.1".into(),
        None,
        Vec::new(),
        true,
        acl_enabled,
        false,
        false,
        false,
        ServiceLocationMode::Disabled,
    )
    .save(pool)
    .await
    .unwrap()
}

fn sent_update(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<xguard_proto::gateway::CoreResponse>,
) -> Option<xguard_proto::gateway::update::Update> {
    match rx.try_recv().ok()?.payload? {
        core_response::Payload::Update(update) => update.update,
        _ => None,
    }
}

#[sqlx::test]
async fn test_firewall_refresh_sends_only_changes(_: PgPoolOptions, options: PgConnectOptions) {
    use xguard_proto::gateway::{FirewallAction, update::Update};

    let pool = setup_pool(options).await;
    let network = firewall_location(&pool, true).await;
    let (tx, mut rx) = unbounded_channel();
    let mut handler = GatewayUpdatesHandler::new(network.clone(), "gateway", Some(&pool), tx);

    // A rules change marks the policy for a re-check; the first one sends it.
    handler
        .handle_event(GatewayCommand::FirewallRulesChanged)
        .await
        .unwrap();
    assert!(handler.firewall_dirty());
    handler.refresh_firewall().await.unwrap();
    assert!(!handler.firewall_dirty());
    let Some(Update::Firewall(policy)) = sent_update(&mut rx) else {
        panic!("expected a firewall policy");
    };
    assert_eq!(policy.default_action, FirewallAction::Drop as i32);
    assert_eq!(policy.revision.len(), 32);

    // Nothing changed: nothing is sent.
    handler.refresh_firewall().await.unwrap();
    assert!(rx.try_recv().is_err());

    // Turning the firewall off on the location: the network update itself carries no policy,
    // and the follow-up refresh has nothing left to send.
    let mut off = network.clone();
    off.acl_enabled = false;
    handler
        .handle_event(GatewayCommand::NetworkModified(off, Vec::new()))
        .await
        .unwrap();
    let Some(Update::Network(config)) = sent_update(&mut rx) else {
        panic!("expected a network update");
    };
    assert!(config.firewall.is_none());
    handler.refresh_firewall().await.unwrap();
    assert!(rx.try_recv().is_err());

    // And back on: the network update carries the policy, so there is no unfiltered window.
    handler
        .handle_event(GatewayCommand::NetworkModified(network, Vec::new()))
        .await
        .unwrap();
    let Some(Update::Network(config)) = sent_update(&mut rx) else {
        panic!("expected a network update");
    };
    assert_eq!(config.firewall.unwrap().revision, policy.revision);
    handler.refresh_firewall().await.unwrap();
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn test_unrelated_events_do_not_touch_the_firewall() {
    let mut handler = test_handler(false);
    let device = Device::new(
        "elsewhere".to_owned(),
        "pubkey".to_owned(),
        1,
        DeviceType::User,
        None,
        true,
    )
    .with_id(1);
    let other_location = DeviceInfo {
        device,
        network_info: vec![DeviceNetworkInfo {
            network_id: 999,
            device_wireguard_ips: Vec::new(),
            preshared_key: None,
            is_authorized: true,
        }],
    };
    handler
        .handle_event(GatewayCommand::DeviceCreated(other_location))
        .await
        .unwrap();
    assert!(!handler.firewall_dirty());
}

#[sqlx::test]
async fn test_network_update_keeps_last_policy_when_compile_fails(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    use xguard_proto::gateway::{FirewallPolicy, update::Update};

    let pool = setup_pool(options).await;
    let network = firewall_location(&pool, true).await;
    let (tx, mut rx) = unbounded_channel();
    let mut handler = GatewayUpdatesHandler::new(network.clone(), "gateway", Some(&pool), tx);
    let installed = FirewallPolicy {
        revision: "installed".into(),
        ..FirewallPolicy::default()
    };
    handler.set_firewall_policy(Some(installed.clone()));

    // The database goes away: the policy can't be compiled.
    pool.close().await;
    handler
        .handle_event(GatewayCommand::NetworkModified(network, Vec::new()))
        .await
        .unwrap();
    let Some(Update::Network(config)) = sent_update(&mut rx) else {
        panic!("expected a network update");
    };
    // The gateway keeps what it enforces, and a refresh is scheduled to retry.
    assert_eq!(config.firewall, Some(installed));
    assert!(handler.firewall_dirty());
    assert!(handler.refresh_firewall().await.is_err());
    assert!(rx.try_recv().is_err());
}
