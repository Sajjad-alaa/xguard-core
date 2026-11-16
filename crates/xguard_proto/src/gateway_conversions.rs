//! Conversions from [`xguard_common::gateway_types`] domain types to their
//! protobuf counterparts. These are the sole serialization boundary between
//! the native gateway command representation and the wire protocol.

use std::net::IpAddr;

use xguard_common::{
    firewall::{CompiledPolicy, PolicyAction, address::AddressRange},
    gateway_types::WireguardPeer,
};

use crate::gateway::{
    AddressSet, FirewallAction, FirewallPolicy, FirewallRule, IpRange, Peer, PortRange, SnatBinding,
};

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

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

impl From<PolicyAction> for FirewallAction {
    fn from(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Accept => Self::Accept,
            PolicyAction::Drop => Self::Drop,
            PolicyAction::Reject => Self::Reject,
        }
    }
}

impl From<&AddressRange> for IpRange {
    fn from(range: &AddressRange) -> Self {
        Self {
            start: address_bytes(range.start()),
            end: address_bytes(range.end()),
        }
    }
}

impl From<&CompiledPolicy> for FirewallPolicy {
    fn from(policy: &CompiledPolicy) -> Self {
        Self {
            revision: policy.revision.clone(),
            default_action: policy
                .default_action
                .map_or(FirewallAction::Unspecified, Into::into)
                .into(),
            address_sets: policy
                .sets
                .iter()
                .zip(0u32..)
                .map(|(ranges, id)| AddressSet {
                    id,
                    ranges: ranges.iter().map(Into::into).collect(),
                })
                .collect(),
            rules: policy
                .rules
                .iter()
                .map(|rule| FirewallRule {
                    id: rule.id.cast_unsigned(),
                    action: FirewallAction::from(rule.action).into(),
                    source_set: rule.source,
                    destination_set: rule.destination,
                    protocols: rule.protocols.iter().map(|&p| u32::from(p)).collect(),
                    destination_ports: rule
                        .ports
                        .iter()
                        .map(|ports| PortRange {
                            start: u32::from(*ports.start()),
                            end: u32::from(*ports.end()),
                        })
                        .collect(),
                })
                .collect(),
            snat_bindings: policy
                .snat
                .iter()
                .map(|binding| SnatBinding {
                    source_set: binding.source,
                    to_address: address_bytes(binding.to),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use xguard_common::firewall::{
        CompiledPolicy, CompiledRule, CompiledSnat, PolicyAction, address::AddressRange,
    };

    use crate::gateway::{FirewallAction, FirewallPolicy};

    #[test]
    fn compiled_policy_converts_to_wire_format() {
        let policy = CompiledPolicy {
            revision: "abc".into(),
            default_action: Some(PolicyAction::Drop),
            sets: vec![
                vec![AddressRange::V4(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 9),
                )],
                vec![AddressRange::single(IpAddr::V6(Ipv6Addr::LOCALHOST))],
            ],
            rules: vec![CompiledRule {
                id: 42,
                action: PolicyAction::Reject,
                source: Some(0),
                destination: None,
                protocols: vec![6],
                ports: vec![443..=443, 8000..=8080],
            }],
            snat: vec![CompiledSnat {
                source: 0,
                to: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            }],
        };
        let wire = FirewallPolicy::from(&policy);
        assert_eq!(wire.revision, "abc");
        assert_eq!(wire.default_action, FirewallAction::Drop as i32);
        assert_eq!(wire.address_sets.len(), 2);
        assert_eq!(wire.address_sets[0].id, 0);
        assert_eq!(wire.address_sets[0].ranges[0].start, [10, 0, 0, 1]);
        assert_eq!(wire.address_sets[0].ranges[0].end, [10, 0, 0, 9]);
        assert_eq!(wire.address_sets[1].ranges[0].start.len(), 16);
        let rule = &wire.rules[0];
        assert_eq!(rule.id, 42);
        assert_eq!(rule.action, FirewallAction::Reject as i32);
        assert_eq!((rule.source_set, rule.destination_set), (Some(0), None));
        assert_eq!(rule.protocols, [6]);
        assert_eq!(
            rule.destination_ports
                .iter()
                .map(|p| (p.start, p.end))
                .collect::<Vec<_>>(),
            [(443, 443), (8000, 8080)]
        );
        assert_eq!(wire.snat_bindings[0].to_address, [203, 0, 113, 7]);

        // Filtering off: the gateway sees an unspecified default action.
        let nat_only = CompiledPolicy {
            default_action: None,
            rules: Vec::new(),
            ..policy
        };
        assert_eq!(
            FirewallPolicy::from(&nat_only).default_action,
            FirewallAction::Unspecified as i32
        );
    }
}
