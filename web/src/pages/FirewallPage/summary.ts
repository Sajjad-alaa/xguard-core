import { m } from '../../paraglide/messages';
import type { FirewallRule, FirewallRuleActionValue } from '../../shared/api/types';
import type { FirewallNames, NamedItem } from './useFirewallNames';

const PROTOCOL_NAMES: Record<number, string> = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  58: 'ICMPv6',
  132: 'SCTP',
};

export const protocolName = (protocol: number) =>
  PROTOCOL_NAMES[protocol] ?? `#${protocol}`;

export const actionLabel = (action: FirewallRuleActionValue) => {
  switch (action) {
    case 'allow':
      return m.firewall_action_allow();
    case 'deny':
      return m.firewall_action_deny();
    case 'reject':
      return m.firewall_action_reject();
  }
};

/** Shows up to two names, then a count, so long selections stay readable in a table cell. */
const someNames = (
  ids: number[],
  items: NamedItem[],
  counter: (count: number) => string,
) => {
  if (ids.length === 0) return [];
  if (ids.length > 2) return [counter(ids.length)];
  const byId = new Map(items.map((i) => [i.id, i.label]));
  return ids.map((id) => byId.get(id) ?? `#${id}`);
};

export const sourcesSummary = (rule: FirewallRule, names: FirewallNames) => {
  if (rule.any_source) return m.firewall_any_source();
  const parts = [
    ...(rule.all_users
      ? [m.firewall_all_users()]
      : someNames(rule.users, names.users, (count) => m.firewall_count_users({ count }))),
    ...someNames(rule.groups, names.groups, (count) =>
      m.firewall_count_groups({ count }),
    ),
    ...(rule.all_network_devices
      ? [m.firewall_all_network_devices()]
      : someNames(rule.devices, names.devices, (count) =>
          m.firewall_count_devices({ count }),
        )),
  ];
  return parts.join(', ');
};

export const destinationsSummary = (rule: FirewallRule) => {
  if (rule.any_destination) return m.firewall_any_destination();
  const shown = rule.destinations.slice(0, 3).join(', ');
  return rule.destinations.length > 3
    ? `${shown} +${rule.destinations.length - 3}`
    : shown;
};

export const servicesSummary = (rule: FirewallRule) => {
  const protocols = rule.protocols.map(protocolName).join('/');
  const ports = rule.ports.join(', ');
  if (!protocols && !ports) return m.firewall_any_service();
  return [protocols, ports].filter(Boolean).join(' ');
};

export const locationsSummary = (rule: FirewallRule, names: FirewallNames) => {
  if (rule.all_locations) return m.firewall_all_locations();
  return someNames(rule.locations, names.locations, (count) =>
    m.firewall_count_locations({ count }),
  ).join(', ');
};

export const isExpired = (rule: FirewallRule) =>
  rule.expires_at !== null && new Date(`${rule.expires_at}Z`) <= new Date();
