//! AllowedIPs derived from firewall rules ("Allowed IPs from firewall rules", the location's
//! `allowed_ips_from_acl` option).
//!
//! With the option on, a device's WireGuard `AllowedIPs` for a location are what that device may
//! reach there according to the location's firewall rules, instead of the location's static
//! list, so every user gets a split tunnel that routes only what they are allowed to use.
//!
//! Which rules apply to a device is decided by the same code the gateway policy is compiled with
//! ([`FirewallRule::active_for_location`], [`rule_source_devices`], [`rule_destination`],
//! [`rule_ports`]), so the routes a client gets and the rules its gateway enforces cannot drift
//! apart. The gateway keeps enforcing the rules; the routes only decide what the client sends
//! into the tunnel.
//!
//! The routes for a device are, merged and deduplicated:
//! - the destinations of the enabled, unexpired **allow** rules at the location whose sources
//!   select the device (any source, all users, its user, one of its user's groups, the device
//!   itself, or all network devices for a network device);
//! - the location's static allowed IPs when such a rule allows **any destination**, or when the
//!   location's default action is **allow** (unmatched traffic is accepted, so the device may
//!   reach everything the location routes);
//! - always the location's VPN networks, and its DNS servers that are inside the VPN (in a VPN
//!   network or in a static allowed network other than a default route), so the gateway and
//!   name resolution keep working even when no rule applies.
//!
//! Deny and reject rules add no routes and remove none: traffic they block still enters the
//! tunnel and the gateway drops it, instead of leaking to the client's local network.
//! When the location's firewall is off the option has no effect (the static list is used),
//! because no rules are enforced there.

use std::{collections::HashSet, net::IpAddr};

use chrono::Utc;
use ipnetwork::IpNetwork;
use sqlx::PgConnection;
use tracing::warn;

use super::{
    address::AddressRange,
    compile::{Destination, normalize, rule_destination, rule_ports, rule_source_devices},
    rule::{FirewallRule, FirewallRuleAction},
};
use crate::db::{Id, models::WireguardNetwork};

/// Most networks one derived AllowedIPs list may hold. Past this, the static list is used
/// (with a warning): the gateway still enforces the rules, and clients are not handed a
/// configuration some WireGuard implementations would refuse.
pub const MAX_DERIVED_NETWORKS: usize = 4096;

/// Effective AllowedIPs of device `device_id` at `location`: derived from the firewall rules
/// when the location has the option on and its firewall enabled, the static list otherwise.
pub async fn effective_allowed_ips(
    conn: &mut PgConnection,
    location: &WireguardNetwork<Id>,
    device_id: Id,
) -> Result<Vec<IpNetwork>, sqlx::Error> {
    if !location.allowed_ips_from_acl || !location.acl_enabled {
        return Ok(location.allowed_ips.clone());
    }
    let rules = applicable_rules(conn, location, device_id).await?;
    let derived = derive_allowed_ips(location, &rules);
    if derived.len() > MAX_DERIVED_NETWORKS {
        warn!(
            "Firewall rules give device {device_id} {} AllowedIPs networks at location {} \
            (limit {MAX_DERIVED_NETWORKS}); using the location's static allowed IPs",
            derived.len(),
            location.name
        );
        return Ok(location.allowed_ips.clone());
    }
    Ok(derived)
}

/// The active rules at `location` whose sources select device `device_id`, in evaluation order.
pub async fn applicable_rules(
    conn: &mut PgConnection,
    location: &WireguardNetwork<Id>,
    device_id: Id,
) -> Result<Vec<FirewallRule>, sqlx::Error> {
    let rules =
        FirewallRule::active_for_location(conn, location.id, Utc::now().naive_utc()).await?;
    let selective: Vec<Id> = rules
        .iter()
        .filter(|rule| !rule.any_source)
        .map(|rule| rule.id)
        .collect();
    let selected: HashSet<Id> = if selective.is_empty() {
        HashSet::new()
    } else {
        rule_source_devices(conn, location.id, &selective, Some(device_id))
            .await?
            .into_iter()
            .map(|(rule_id, _, _)| rule_id)
            .collect()
    };
    Ok(rules
        .into_iter()
        .filter(|rule| rule.any_source || selected.contains(&rule.id))
        .collect())
}

/// AllowedIPs from `rules`, the rules that apply to one device at `location` (see the module
/// documentation). Sorted, without overlaps, in as few CIDR networks as cover the result.
#[must_use]
pub fn derive_allowed_ips(
    location: &WireguardNetwork<Id>,
    rules: &[FirewallRule],
) -> Vec<IpNetwork> {
    let mut ranges: Vec<AddressRange> = Vec::new();
    let static_ranges = || {
        location
            .allowed_ips
            .iter()
            .map(|net| AddressRange::network(*net))
    };
    let mut route_static = location.acl_default_allow;

    for rule in rules {
        if rule.action != FirewallRuleAction::Allow || rule_ports(rule).is_none() {
            continue;
        }
        match rule_destination(rule) {
            Some(Destination::Any) => route_static = true,
            Some(Destination::Ranges(destinations)) => ranges.extend(destinations),
            None => {}
        }
    }
    if route_static {
        ranges.extend(static_ranges());
    }

    // Always routed: the VPN networks, and DNS servers reached through the VPN.
    let vpn_ranges: Vec<AddressRange> = location
        .address()
        .iter()
        .map(|net| AddressRange::network(*net))
        .collect();
    let inside: Vec<AddressRange> = vpn_ranges
        .iter()
        .copied()
        .chain(
            location
                .allowed_ips
                .iter()
                .filter(|net| net.prefix() > 0)
                .map(|net| AddressRange::network(*net)),
        )
        .collect();
    ranges.extend(vpn_ranges);
    ranges.extend(
        dns_servers(location)
            .filter(|dns| inside.iter().any(|range| range.contains(*dns)))
            .map(AddressRange::single),
    );

    normalize(ranges)
        .iter()
        .flat_map(AddressRange::to_networks)
        .collect()
}

/// The IP addresses among the location's DNS entries (the rest are search domains).
fn dns_servers(location: &WireguardNetwork<Id>) -> impl Iterator<Item = IpAddr> + '_ {
    location
        .dns
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| entry.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;

    use super::*;
    use crate::db::models::wireguard::ServiceLocationMode;

    fn location(
        static_ips: &[&str],
        default_allow: bool,
        dns: Option<&str>,
    ) -> WireguardNetwork<Id> {
        WireguardNetwork::new(
            "office".into(),
            51820,
            "vpn.xguard.local".into(),
            dns.map(Into::into),
            static_ips
                .iter()
                .map(|net| net.parse().unwrap())
                .collect::<Vec<IpNetwork>>(),
            true,
            true,
            default_allow,
            true,
            false,
            ServiceLocationMode::Disabled,
        )
        .set_address(vec!["10.6.0.1/24".parse().unwrap()])
        .unwrap()
        .with_id(1)
    }

    fn rule(action: FirewallRuleAction, destinations: &[&str]) -> FirewallRule {
        FirewallRule {
            id: 1,
            name: "rule".into(),
            description: String::new(),
            enabled: true,
            priority: 1000,
            action,
            all_locations: true,
            locations: Vec::new(),
            any_source: true,
            all_users: false,
            all_network_devices: false,
            users: Vec::new(),
            groups: Vec::new(),
            devices: Vec::new(),
            any_destination: destinations.is_empty(),
            destinations: destinations.iter().map(|d| (*d).to_string()).collect(),
            protocols: Vec::new(),
            ports: Vec::new(),
            expires_at: None,
            created_at: NaiveDateTime::default(),
            updated_at: NaiveDateTime::default(),
        }
    }

    fn allow(destinations: &[&str]) -> FirewallRule {
        rule(FirewallRuleAction::Allow, destinations)
    }

    fn derived(location: &WireguardNetwork<Id>, rules: &[FirewallRule]) -> Vec<String> {
        derive_allowed_ips(location, rules)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn no_rules_route_only_the_vpn_network() {
        let office = location(&["0.0.0.0/0"], false, None);
        assert_eq!(derived(&office, &[]), ["10.6.0.0/24"]);
    }

    #[test]
    fn overlapping_and_adjacent_destinations_are_merged() {
        let office = location(&["0.0.0.0/0"], false, None);
        let rules = [
            allow(&["192.168.0.0/24", "192.168.0.128/25"]),
            allow(&["192.168.1.0/24", "192.168.0.7"]),
            // Overlaps the VPN network.
            allow(&["10.6.0.0/25"]),
            allow(&["fd00::/64", "fd00::1"]),
        ];
        assert_eq!(
            derived(&office, &rules),
            ["10.6.0.0/24", "192.168.0.0/23", "fd00::/64"]
        );
    }

    #[test]
    fn ranges_become_cidrs() {
        let office = location(&[], false, None);
        assert_eq!(
            derived(&office, &[allow(&["172.16.0.1-172.16.0.6"])]),
            [
                "10.6.0.0/24",
                "172.16.0.1/32",
                "172.16.0.2/31",
                "172.16.0.4/31",
                "172.16.0.6/32"
            ]
        );
    }

    #[test]
    fn deny_and_reject_rules_add_and_remove_nothing() {
        let office = location(&["0.0.0.0/0"], false, None);
        let rules = [
            rule(FirewallRuleAction::Deny, &["192.168.1.5"]),
            rule(FirewallRuleAction::Reject, &["172.16.0.0/12"]),
            // A deny for "any destination" does not mean "route everything".
            rule(FirewallRuleAction::Deny, &[]),
            allow(&["192.168.1.0/24"]),
        ];
        assert_eq!(derived(&office, &rules), ["10.6.0.0/24", "192.168.1.0/24"]);
    }

    #[test]
    fn any_destination_and_default_allow_route_the_static_list() {
        let office = location(&["10.0.0.0/8", "192.168.0.0/16"], false, None);
        assert_eq!(
            derived(&office, &[allow(&["172.16.0.0/12"]), allow(&[])]),
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "the VPN network is inside 10.0.0.0/8"
        );

        let open = location(&["192.168.0.0/16"], true, None);
        assert_eq!(derived(&open, &[]), ["10.6.0.0/24", "192.168.0.0/16"]);

        let full = location(&["0.0.0.0/0", "::/0"], false, None);
        assert_eq!(derived(&full, &[allow(&[])]), ["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn dns_servers_inside_the_vpn_are_routed() {
        // 10.6.0.53 is in the VPN network, 192.168.5.53 in a static network, 1.1.1.1 only in
        // the default route: it stays outside the tunnel.
        let office = location(
            &["0.0.0.0/0", "192.168.5.0/24"],
            false,
            Some("10.6.0.53, 192.168.5.53,1.1.1.1, corp.example.com"),
        );
        assert_eq!(derived(&office, &[]), ["10.6.0.0/24", "192.168.5.53/32"]);
    }

    #[test]
    fn rules_the_gateway_would_skip_add_nothing() {
        let office = location(&[], false, None);
        let mut broken_ports = allow(&["192.168.1.0/24"]);
        broken_ports.ports = vec!["not a port".into()];
        let mut broken_destinations = allow(&["192.168.2.0/24"]);
        broken_destinations.destinations = vec!["garbage".into()];
        assert_eq!(
            derived(&office, &[broken_ports, broken_destinations]),
            ["10.6.0.0/24"]
        );
    }

    #[test]
    fn protocol_and_port_rules_route_their_addresses() {
        let office = location(&[], false, None);
        let mut web = allow(&["192.168.1.10"]);
        web.protocols = vec![6];
        web.ports = vec!["443".into()];
        assert_eq!(derived(&office, &[web]), ["10.6.0.0/24", "192.168.1.10/32"]);
    }
}
