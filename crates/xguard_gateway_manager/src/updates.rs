use std::net::IpAddr;

use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use tonic::{Code, Status};
use xguard_common::{
    db::{
        Id,
        models::{DeviceNetworkInfo, WireguardNetwork, wireguard::DEFAULT_WIREGUARD_MTU},
    },
    firewall,
    gateway_event::GatewayCommand,
    gateway_types::WireguardPeer,
    secret::SecretStringWrapper,
};
use xguard_proto::gateway::{
    Configuration, CoreResponse, FirewallPolicy, Peer, Update, UpdateType, core_response, update,
};

/// Helper struct for handling gateway events.
pub(crate) struct GatewayUpdatesHandler<'a> {
    network: WireguardNetwork<Id>,
    gateway_name: &'a str,
    pool: Option<&'a PgPool>,
    session_authorization_required: bool,
    tx: UnboundedSender<CoreResponse>,
    /// The firewall policy the gateway has, `None` when it has none.
    firewall_policy: Option<FirewallPolicy>,
    /// Something changed that may change the firewall policy.
    firewall_dirty: bool,
}

impl<'a> GatewayUpdatesHandler<'a> {
    #[must_use]
    pub(crate) fn new(
        network: WireguardNetwork<Id>,
        gateway_name: &'a str,
        pool: Option<&'a PgPool>,
        tx: UnboundedSender<CoreResponse>,
    ) -> Self {
        // Sane default. It will be updated in `start()`.
        let session_authorization_required = network.mfa_enabled;
        Self {
            network,
            gateway_name,
            pool,
            session_authorization_required,
            tx,
            firewall_policy: None,
            firewall_dirty: false,
        }
    }

    /// Records the firewall policy sent with the initial configuration.
    pub(crate) fn set_firewall_policy(&mut self, policy: Option<FirewallPolicy>) {
        self.firewall_policy = policy;
    }

    fn firewall_revision(&self) -> Option<&str> {
        self.firewall_policy.as_ref().map(|p| p.revision.as_str())
    }

    /// The policy to send with a network update. If it can't be compiled right now, the gateway
    /// keeps the one it has (never an unfiltered window) and a refresh retries shortly.
    async fn policy_for_network_update(
        &mut self,
        network: &WireguardNetwork<Id>,
    ) -> Option<FirewallPolicy> {
        match self.compile_firewall(network).await {
            Ok(policy) => policy.as_ref().map(FirewallPolicy::from),
            Err(_) => {
                self.firewall_dirty = true;
                self.firewall_policy.clone()
            }
        }
    }

    pub(crate) fn firewall_dirty(&self) -> bool {
        self.firewall_dirty
    }

    pub(crate) fn mark_firewall_dirty(&mut self) {
        self.firewall_dirty = true;
    }

    /// Compiles the firewall policy for `network`. Without a database (tests) there is none.
    async fn compile_firewall(
        &self,
        network: &WireguardNetwork<Id>,
    ) -> Result<Option<firewall::CompiledPolicy>, Status> {
        let Some(pool) = self.pool else {
            return Ok(None);
        };
        let mut conn = pool.acquire().await.map_err(|err| {
            Status::internal(format!("Failed to get a database connection: {err}"))
        })?;
        firewall::compile(&mut conn, network).await.map_err(|err| {
            let msg = format!("Failed to compile the firewall for {network}: {err}");
            error!(msg);
            Status::internal(msg)
        })
    }

    /// Recompiles the firewall policy and sends it if its revision changed.
    pub(crate) async fn refresh_firewall(&mut self) -> Result<(), Status> {
        self.firewall_dirty = false;
        let policy = self.compile_firewall(&self.network).await?;
        let revision = policy.as_ref().map(|p| p.revision.clone());
        if revision.as_deref() == self.firewall_revision() {
            debug!("Firewall policy for {} is unchanged", self.network);
            return Ok(());
        }
        let wire = policy.as_ref().map(FirewallPolicy::from);
        let update = match &wire {
            Some(wire) => update::Update::Firewall(wire.clone()),
            None => update::Update::DisableFirewall(()),
        };
        self.send_update(Update {
            update_type: UpdateType::Modify as i32,
            update: Some(update),
        })?;
        info!(
            "Sent firewall policy {} to gateway {} for {}",
            revision.as_deref().unwrap_or("(off)"),
            self.gateway_name,
            self.network
        );
        self.firewall_policy = wire;
        Ok(())
    }

    fn send_update(&self, update: Update) -> Result<(), Status> {
        self.tx
            .send(CoreResponse {
                id: 0,
                payload: Some(core_response::Payload::Update(update)),
            })
            .map_err(|err| {
                let msg = format!("Failed to send an update for {}: {err}", self.network);
                error!(msg);
                Status::internal(msg)
            })
    }

    /// Whether `command` can change this location's firewall policy (device addresses, the
    /// location's firewall settings or the rules themselves).
    fn affects_firewall(&self, command: &GatewayCommand) -> bool {
        let here =
            |info: &[DeviceNetworkInfo]| info.iter().any(|i| i.network_id == self.network.id);
        match command {
            GatewayCommand::FirewallRulesChanged => true,
            GatewayCommand::DeviceCreated(device)
            | GatewayCommand::DeviceModified(device)
            | GatewayCommand::DeviceDeleted(device) => here(&device.network_info),
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_session_authorization_required(&mut self, value: bool) {
        self.session_authorization_required = value;
    }

    async fn refresh_session_authorization_required(&mut self) {
        if self.network.mfa_enabled {
            self.session_authorization_required = true;
            return;
        }

        let Some(pool) = self.pool else {
            self.session_authorization_required = false;
            return;
        };

        self.session_authorization_required = match self.network.has_postures(pool).await {
            Ok(has_postures) => has_postures,
            Err(err) => {
                error!(
                    "Failed to fetch postures for location {}: {err}",
                    self.network
                );
                false
            }
        };
    }

    #[must_use]
    pub(crate) fn runtime_peer_update(
        &self,
        peer_label: &str,
        peer_pubkey: String,
        allowed_ips: Vec<String>,
        is_authorized: bool,
        preshared_key: Option<SecretStringWrapper>,
    ) -> Option<Peer> {
        if !self.session_authorization_required {
            return Some(Peer {
                pubkey: peer_pubkey,
                allowed_ips,
                preshared_key: None,
                keepalive_interval: Some(self.network.keepalive_interval.cast_unsigned()),
            });
        }

        if !is_authorized {
            debug!(
                "Skipping gateway peer update for WireGuard device {peer_label} in \
                runtime-authorized location {} because there is no active VPN session",
                self.network.name
            );
            return None;
        }

        let Some(preshared_key) = preshared_key else {
            debug!(
                "Skipping gateway peer update for WireGuard device {peer_label} in location {} \
                because the runtime preshared key is missing",
                self.network.name
            );
            return None;
        };

        Some(Peer {
            pubkey: peer_pubkey,
            allowed_ips,
            preshared_key: Some(preshared_key.expose_secret().to_owned()),
            keepalive_interval: Some(self.network.keepalive_interval.cast_unsigned()),
        })
    }

    fn send_runtime_device_update(
        &self,
        peer_label: &str,
        peer_pubkey: String,
        network_info: &DeviceNetworkInfo,
        update_type: UpdateType,
    ) -> Result<(), Status> {
        let allowed_ips = network_info
            .device_wireguard_ips
            .iter()
            .map(IpAddr::to_string)
            .collect();

        let Some(peer) = self.runtime_peer_update(
            peer_label,
            peer_pubkey,
            allowed_ips,
            network_info.is_authorized,
            network_info.preshared_key.clone(),
        ) else {
            return Ok(());
        };

        self.send_peer_update(peer, update_type)
    }

    /// Must be called before handling events.
    pub(crate) async fn start(&mut self) {
        info!(
            "Starting update stream to gateway: {}, network {}",
            self.gateway_name, self.network
        );
        self.refresh_session_authorization_required().await;
    }

    /// Process incoming Gateway event
    ///
    /// Every handler receives all events, so it must skip those for other networks.
    pub(crate) async fn handle_event(&mut self, update: GatewayCommand) -> Result<(), Status> {
        debug!("Received WireGuard update: {update:?}");
        if self.affects_firewall(&update) {
            self.firewall_dirty = true;
        }
        match update {
            GatewayCommand::NetworkCreated(network) => {
                if network.id == self.network.id {
                    let policy = self.policy_for_network_update(&network).await;
                    let result = self.send_network_update(
                        &network,
                        Vec::new(),
                        policy.clone(),
                        UpdateType::Create,
                    );
                    self.firewall_policy = policy;
                    result
                } else {
                    Ok(())
                }
            }
            GatewayCommand::NetworkModified(network, peers) => {
                if network.id == self.network.id {
                    // A network update replaces the gateway's whole configuration, firewall
                    // included, so it carries the current policy: never a window without it.
                    let policy = self.policy_for_network_update(&network).await;
                    let result = self.send_network_update(
                        &network,
                        peers,
                        policy.clone(),
                        UpdateType::Modify,
                    );
                    self.firewall_policy = policy;
                    // update stored network data
                    self.network = network;
                    self.refresh_session_authorization_required().await;
                    result
                } else {
                    Ok(())
                }
            }
            GatewayCommand::FirewallRulesChanged => Ok(()),
            GatewayCommand::NetworkDeleted(network_id, network_name) => {
                if network_id == self.network.id {
                    self.send_network_delete(&network_name)
                } else {
                    Ok(())
                }
            }
            GatewayCommand::DeviceCreated(device) => {
                // check if a peer has to be added in the current network
                match device
                    .network_info
                    .iter()
                    .find(|info| info.network_id == self.network.id)
                {
                    Some(network_info) => self.send_runtime_device_update(
                        &device.device.name,
                        device.device.wireguard_pubkey,
                        network_info,
                        UpdateType::Create,
                    ),
                    None => Ok(()),
                }
            }
            GatewayCommand::DeviceModified(device) => {
                // check if a peer has to be updated in the current network
                match device
                    .network_info
                    .iter()
                    .find(|info| info.network_id == self.network.id)
                {
                    Some(network_info) => self.send_runtime_device_update(
                        &device.device.name,
                        device.device.wireguard_pubkey,
                        network_info,
                        UpdateType::Modify,
                    ),
                    None => Ok(()),
                }
            }
            GatewayCommand::DeviceDeleted(device) => {
                // check if a peer has to be updated in the current network
                match device
                    .network_info
                    .iter()
                    .find(|info| info.network_id == self.network.id)
                {
                    Some(_) => self.send_peer_delete(&device.device.wireguard_pubkey),
                    None => Ok(()),
                }
            }
            GatewayCommand::VpnSessionDeauthorized(location_id, device) => {
                if location_id == self.network.id {
                    self.send_peer_delete(&device.wireguard_pubkey)
                } else {
                    Ok(())
                }
            }
            GatewayCommand::VpnSessionAuthorized(location_id, device, network_info) => {
                if location_id == self.network.id {
                    if network_info.network_id != location_id {
                        error!(
                            "Received VPN authorization success event for location {location_id} \
                            with invalid runtime network info: {network_info:?}"
                        );
                        return Ok(());
                    }

                    self.send_runtime_device_update(
                        &device.name,
                        device.wireguard_pubkey,
                        &network_info,
                        UpdateType::Create,
                    )
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Sends updated network configuration
    fn send_network_update(
        &self,
        network: &WireguardNetwork<Id>,
        peers: Vec<WireguardPeer>,
        firewall: Option<FirewallPolicy>,
        update_type: UpdateType,
    ) -> Result<(), Status> {
        debug!("Sending network update for network {network}");
        let peers = peers.into_iter().map(Into::into).collect();
        if let Err(err) = self.tx.send(CoreResponse {
            id: 0,
            payload: Some(core_response::Payload::Update(Update {
                update_type: update_type as i32,
                update: Some(update::Update::Network(Configuration {
                    name: network.name.clone(),
                    private_key: network.prvkey.clone(),
                    addresses: network.address().iter().map(ToString::to_string).collect(),
                    port: network.port.cast_unsigned(),
                    peers,
                    mtu: network.mtu.cast_unsigned(),
                    fwmark: network.fwmark as u32,
                    firewall,
                })),
            })),
        }) {
            let msg = format!(
                "Failed to send network update, network {network}, update type: {update_type:?}, \
                error: {err}",
            );
            error!(msg);
            Err(Status::new(Code::Internal, msg))
        } else {
            debug!("Network update sent for network {network}");
            Ok(())
        }
    }

    /// Sends delete network command to gateway
    fn send_network_delete(&self, network_name: &str) -> Result<(), Status> {
        debug!(
            "Sending network delete command for network {}",
            self.network
        );
        if let Err(err) = self.tx.send(CoreResponse {
            id: 0,
            payload: Some(core_response::Payload::Update(Update {
                update_type: UpdateType::Delete as i32,
                update: Some(update::Update::Network(Configuration {
                    name: network_name.to_owned(),
                    private_key: String::new(),
                    addresses: Vec::new(),
                    port: 0,
                    peers: Vec::new(),
                    mtu: DEFAULT_WIREGUARD_MTU.cast_unsigned(),
                    fwmark: 0,
                    firewall: None,
                })),
            })),
        }) {
            let msg = format!(
                "Failed to send network update, network {}, update type: 3 (DELETE), error: {err}",
                self.network,
            );
            error!(msg);
            return Err(Status::new(Code::Internal, msg));
        }
        debug!("Network delete command sent for network {}", self.network);
        Ok(())
    }

    /// Send update peer command to gateway
    fn send_peer_update(&self, peer: Peer, update_type: UpdateType) -> Result<(), Status> {
        debug!("Sending peer update for network {}", self.network);
        if let Err(err) = self.tx.send(CoreResponse {
            id: 0,
            payload: Some(core_response::Payload::Update(Update {
                update_type: update_type as i32,
                update: Some(update::Update::Peer(peer)),
            })),
        }) {
            let msg = format!(
                "Failed to send peer update for network {}, update type: {update_type:?}, \
                error: {err}",
                self.network,
            );
            error!(msg);
            return Err(Status::new(Code::Internal, msg));
        }
        debug!("Peer update sent for network {}", self.network);
        Ok(())
    }

    /// Send delete peer command to gateway
    fn send_peer_delete(&self, peer_pubkey: &str) -> Result<(), Status> {
        debug!("Sending peer delete for network {}", self.network);
        if let Err(err) = self.tx.send(CoreResponse {
            id: 0,
            payload: Some(core_response::Payload::Update(Update {
                update_type: UpdateType::Delete as i32,
                update: Some(update::Update::Peer(Peer {
                    pubkey: peer_pubkey.into(),
                    allowed_ips: Vec::new(),
                    preshared_key: None,
                    keepalive_interval: None,
                })),
            })),
        }) {
            let msg = format!(
                "Failed to send peer update for network {}, peer {peer_pubkey}, update type: 3 \
                (DELETE), error: {err}",
                self.network,
            );
            error!(msg);
            return Err(Status::new(Code::Internal, msg));
        }
        debug!("Peer delete command sent for network {}", self.network);
        Ok(())
    }
}
