//! Compiles the rules for one location into the policy its gateways enforce.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    ops::RangeInclusive,
};

use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use super::{
    address::{AddressRange, parse_destination, parse_ports},
    rule::{FirewallRule, FirewallRuleAction},
};
use crate::db::{Id, models::WireguardNetwork};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PolicyAction {
    Accept,
    Drop,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompiledRule {
    pub id: Id,
    pub action: PolicyAction,
    pub source: Option<u32>,
    pub destination: Option<u32>,
    pub protocols: Vec<u8>,
    pub ports: Vec<RangeInclusive<u16>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompiledSnat {
    pub source: u32,
    pub to: IpAddr,
}

/// What a location's gateways enforce. Set IDs index into `sets`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompiledPolicy {
    /// Hash of everything below; equal revisions mean equal policies.
    pub revision: String,
    /// `None` when packet filtering is off and only SNAT applies.
    pub default_action: Option<PolicyAction>,
    pub sets: Vec<Vec<AddressRange>>,
    pub rules: Vec<CompiledRule>,
    pub snat: Vec<CompiledSnat>,
}

/// Sorts, then joins overlapping and adjacent ranges of the same IP version.
#[must_use]
pub fn normalize(mut ranges: Vec<AddressRange>) -> Vec<AddressRange> {
    ranges.sort_unstable();
    let mut out: Vec<AddressRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = out.last_mut() {
            let joined = match (*last, range) {
                (AddressRange::V4(ls, le), AddressRange::V4(s, e))
                    if u32::from(le)
                        .checked_add(1)
                        .is_none_or(|n| u32::from(s) <= n) =>
                {
                    Some(AddressRange::V4(ls, le.max(e)))
                }
                (AddressRange::V6(ls, le), AddressRange::V6(s, e))
                    if u128::from(le)
                        .checked_add(1)
                        .is_none_or(|n| u128::from(s) <= n) =>
                {
                    Some(AddressRange::V6(ls, le.max(e)))
                }
                _ => None,
            };
            if let Some(joined) = joined {
                *last = joined;
                continue;
            }
        }
        out.push(range);
    }
    out
}

/// Gives identical address sets one ID.
#[derive(Default)]
struct SetInterner {
    ids: BTreeMap<Vec<AddressRange>, u32>,
    sets: Vec<Vec<AddressRange>>,
}

impl SetInterner {
    fn intern(&mut self, ranges: Vec<AddressRange>) -> u32 {
        let ranges = normalize(ranges);
        if let Some(&id) = self.ids.get(&ranges) {
            return id;
        }
        let id = u32::try_from(self.sets.len()).expect("fewer than 2^32 sets");
        self.sets.push(ranges.clone());
        self.ids.insert(ranges, id);
        id
    }
}

fn action(action: FirewallRuleAction) -> PolicyAction {
    match action {
        FirewallRuleAction::Allow => PolicyAction::Accept,
        FirewallRuleAction::Deny => PolicyAction::Drop,
        FirewallRuleAction::Reject => PolicyAction::Reject,
    }
}

fn host_ranges(addresses: &[IpNetwork]) -> impl Iterator<Item = AddressRange> + '_ {
    // Device VPN addresses are host addresses; ignore any mask stored with them.
    addresses.iter().map(|net| AddressRange::single(net.ip()))
}

/// VPN addresses at `location_id` of the devices each rule selects.
async fn rule_sources(
    conn: &mut PgConnection,
    location_id: Id,
    rule_ids: &[Id],
) -> Result<HashMap<Id, Vec<AddressRange>>, sqlx::Error> {
    // One query for all rules. Disabled users' devices never count as a source.
    let rows: Vec<(Id, Vec<IpNetwork>)> = sqlx::query_as(
        "WITH rules AS ( \
            SELECT id, all_users, all_network_devices FROM firewall_rule WHERE id = ANY($2) \
        ), rule_users AS ( \
            SELECT r.id rule_id, u.id user_id FROM rules r JOIN \"user\" u ON r.all_users \
            UNION SELECT ru.rule_id, ru.user_id FROM firewall_rule_user ru \
                JOIN rules r ON r.id = ru.rule_id \
            UNION SELECT rg.rule_id, gu.user_id FROM firewall_rule_group rg \
                JOIN rules r ON r.id = rg.rule_id JOIN group_user gu ON gu.group_id = rg.group_id \
        ), location_devices AS ( \
            SELECT d.id device_id, d.user_id, d.device_type, wnd.wireguard_ips, u.is_active \
            FROM wireguard_network_device wnd JOIN device d ON d.id = wnd.device_id \
            JOIN \"user\" u ON u.id = d.user_id WHERE wnd.wireguard_network_id = $1 \
        ) \
        SELECT ru.rule_id, ld.wireguard_ips FROM rule_users ru \
            JOIN location_devices ld ON ld.user_id = ru.user_id \
            WHERE ld.device_type = 'user' AND ld.is_active \
        UNION ALL SELECT r.id, ld.wireguard_ips FROM rules r \
            JOIN location_devices ld ON r.all_network_devices AND ld.device_type = 'network' \
        UNION ALL SELECT rd.rule_id, ld.wireguard_ips FROM firewall_rule_device rd \
            JOIN rules r ON r.id = rd.rule_id \
            JOIN location_devices ld ON ld.device_id = rd.device_id \
            WHERE ld.device_type = 'network' OR ld.is_active",
    )
    .bind(location_id)
    .bind(rule_ids)
    .fetch_all(&mut *conn)
    .await?;

    let mut sources: HashMap<Id, Vec<AddressRange>> = HashMap::new();
    for (rule_id, addresses) in rows {
        sources
            .entry(rule_id)
            .or_default()
            .extend(host_ranges(&addresses));
    }
    Ok(sources)
}

/// SNAT bindings at `location_id`: each active user's device addresses and their public IP.
async fn snat_bindings(
    conn: &mut PgConnection,
    location_id: Id,
) -> Result<Vec<(IpNetwork, Vec<IpNetwork>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT b.public_ip, \
            ARRAY(SELECT unnest(wnd.wireguard_ips) FROM wireguard_network_device wnd \
                JOIN device d ON d.id = wnd.device_id \
                WHERE wnd.wireguard_network_id = b.location_id AND d.user_id = b.user_id \
                AND d.device_type = 'user') \
        FROM user_snat_binding b JOIN \"user\" u ON u.id = b.user_id AND u.is_active \
        WHERE b.location_id = $1 ORDER BY b.id",
    )
    .bind(location_id)
    .fetch_all(&mut *conn)
    .await
}

fn revision(policy: &CompiledPolicy) -> String {
    let canonical = serde_json::to_vec(&(
        &policy.default_action,
        &policy.sets,
        &policy.rules,
        &policy.snat,
    ))
    .expect("policy serializes");
    let digest = Sha256::digest(canonical);
    crate::hex::to_lower_hex(&digest[..16])
}

/// Builds the policy for `location`, or `None` when it has neither filtering nor SNAT.
pub async fn compile(
    conn: &mut PgConnection,
    location: &WireguardNetwork<Id>,
) -> Result<Option<CompiledPolicy>, sqlx::Error> {
    let mut sets = SetInterner::default();
    let mut rules = Vec::new();
    let default_action = if location.acl_enabled {
        Some(if location.acl_default_allow {
            PolicyAction::Accept
        } else {
            PolicyAction::Drop
        })
    } else {
        None
    };

    if default_action.is_some() {
        let stored =
            FirewallRule::active_for_location(conn, location.id, Utc::now().naive_utc()).await?;
        let ids: Vec<Id> = stored.iter().map(|r| r.id).collect();
        let mut sources = rule_sources(conn, location.id, &ids).await?;

        for rule in stored {
            let source = if rule.any_source {
                None
            } else {
                match sources.remove(&rule.id) {
                    Some(ranges) if !ranges.is_empty() => Some(sets.intern(ranges)),
                    // Nobody it selects has a device here: the rule cannot match.
                    _ => continue,
                }
            };
            let destination = if rule.any_destination {
                None
            } else {
                // Stored destinations were validated on write; skip anything that no longer
                // parses rather than widening the rule.
                let ranges: Vec<_> = rule
                    .destinations
                    .iter()
                    .filter_map(|d| parse_destination(d).ok().map(|(_, r)| r))
                    .collect();
                if ranges.is_empty() {
                    continue;
                }
                Some(sets.intern(ranges))
            };
            let ports: Vec<_> = rule
                .ports
                .iter()
                .filter_map(|p| parse_ports(p).ok().map(|(_, r)| r))
                .collect();
            if ports.len() != rule.ports.len() {
                continue;
            }
            rules.push(CompiledRule {
                id: rule.id,
                action: action(rule.action),
                source,
                destination,
                protocols: rule
                    .protocols
                    .iter()
                    .filter_map(|&p| u8::try_from(p).ok())
                    .collect(),
                ports,
            });
        }
    }

    let mut snat = Vec::new();
    for (public_ip, addresses) in snat_bindings(conn, location.id).await? {
        let ranges: Vec<_> = host_ranges(&addresses).collect();
        if ranges.is_empty() {
            continue;
        }
        snat.push(CompiledSnat {
            source: sets.intern(ranges),
            to: public_ip.ip(),
        });
    }

    if default_action.is_none() && snat.is_empty() {
        return Ok(None);
    }
    let mut policy = CompiledPolicy {
        revision: String::new(),
        default_action,
        sets: sets.sets,
        rules,
        snat,
    };
    policy.revision = revision(&policy);
    Ok(Some(policy))
}
