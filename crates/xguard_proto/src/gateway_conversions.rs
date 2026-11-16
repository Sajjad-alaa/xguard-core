//! Conversions from [`xguard_common::gateway_types`] domain types to their
//! protobuf counterparts. These are the sole serialization boundary between
//! the native gateway command representation and the wire protocol.

use xguard_common::gateway_types::WireguardPeer;

use crate::gateway::Peer;

impl From<WireguardPeer> for Peer {
    fn from(p: WireguardPeer) -> Self {
        Self {
            pubkey: p.pubkey,
            allowed_ips: p.allowed_ips,
            preshared_key: p.preshared_key.map(|key| key.expose_secret().to_owned()),
            keepalive_interval: p.keepalive_interval,
        }
    }
}
