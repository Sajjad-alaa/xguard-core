//! Native Rust types for data carried in [`crate::gateway_event::GatewayCommand`] variants.
//!
//! These are domain types; conversion to protobuf wire types happens at the
//! serialization boundary (gateway manager) via `From` impls in `xguard_proto`.

use crate::secret::SecretStringWrapper;

/// A WireGuard peer entry to be configured on a gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct WireguardPeer {
    pub pubkey: String,
    pub allowed_ips: Vec<String>,
    pub preshared_key: Option<SecretStringWrapper>,
    pub keepalive_interval: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::WireguardPeer;
    use crate::secret::SecretStringWrapper;

    #[test]
    fn wireguard_peer_debug_redacts_preshared_key() {
        let peer = WireguardPeer {
            pubkey: String::new(),
            allowed_ips: Vec::new(),
            preshared_key: Some(SecretStringWrapper::from("wireguard-peer-secret")),
            keepalive_interval: None,
        };

        let debug = format!("{peer:?}");
        assert!(!debug.contains("wireguard-peer-secret"));
        assert!(debug.contains("preshared_key: Some("));
    }
}
