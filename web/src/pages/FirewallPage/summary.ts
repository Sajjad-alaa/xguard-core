import { m } from '../../paraglide/messages';
import type { FirewallRule, FirewallRuleActionValue } from '../../shared/api/types';
import type { TableBadgeItem } from '../../shared/components/TableBadgesCell/TableBadgesCell';
import type { BadgeVariantValue } from '../../shared/xguard-ui/components/Badge/types';
import type { IconKindValue } from '../../shared/xguard-ui/components/Icon/icon-types';
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

const byId = (items: NamedItem[]) => new Map(items.map((i) => [i.id, i.label]));

/** Every source of a rule as a badge, in the order the editor shows them. */
export const sourceItems = (
  rule: FirewallRule,
  names: FirewallNames,
): TableBadgeItem[] => {
  if (rule.any_source) {
    return [{ key: 'any', label: m.firewall_any_source(), icon: 'globe' }];
  }
  const users = byId(names.users);
  const groups = byId(names.groups);
  const devices = byId(names.devices);
  return [
    ...(rule.all_users
      ? [{ key: 'all-users', label: m.firewall_all_users(), icon: 'users' as const }]
      : rule.users.map((id) => ({
          key: `user-${id}`,
          label: users.get(id) ?? `#${id}`,
          icon: 'user' as const,
        }))),
    ...rule.groups.map((id) => ({
      key: `group-${id}`,
      label: groups.get(id) ?? `#${id}`,
      icon: 'groups' as const,
    })),
    ...(rule.all_network_devices
      ? [
          {
            key: 'all-devices',
            label: m.firewall_all_network_devices(),
            icon: 'devices' as const,
          },
        ]
      : rule.devices.map((id) => ({
          key: `device-${id}`,
          label: devices.get(id) ?? `#${id}`,
          icon: 'devices' as const,
        }))),
  ];
};

export const destinationItems = (rule: FirewallRule): TableBadgeItem[] =>
  rule.any_destination
    ? [{ key: 'any', label: m.firewall_any_destination(), icon: 'globe' }]
    : rule.destinations.map((address) => ({
        key: address,
        label: address,
        variant: 'outlined',
      }));

/** Protocols as badges, followed by the ports they cover. */
export const serviceItems = (rule: FirewallRule): TableBadgeItem[] => {
  const protocols: TableBadgeItem[] = rule.protocols.map((protocol) => ({
    key: `proto-${protocol}`,
    label: protocolName(protocol),
    variant: 'plan',
  }));
  const ports: TableBadgeItem[] = rule.ports.map((port) => ({
    key: `port-${port}`,
    label: port,
    variant: 'outlined',
  }));
  if (protocols.length === 0 && ports.length === 0) {
    return [{ key: 'any', label: m.firewall_any_service() }];
  }
  return [...protocols, ...ports];
};

export const locationItems = (
  rule: FirewallRule,
  names: FirewallNames,
): TableBadgeItem[] => {
  if (rule.all_locations) {
    return [
      {
        key: 'all',
        label: m.firewall_all_locations(),
        icon: 'check-filled',
        variant: 'success',
      },
    ];
  }
  const locations = byId(names.locations);
  return rule.locations.map((id) => ({
    key: `location-${id}`,
    label: locations.get(id) ?? `#${id}`,
    icon: 'location',
  }));
};

export const actionVariant = (action: FirewallRuleActionValue): BadgeVariantValue =>
  action === 'allow' ? 'success' : 'critical';

export const actionIcon = (action: FirewallRuleActionValue): IconKindValue => {
  switch (action) {
    case 'allow':
      return 'check-circle';
    case 'deny':
      return 'disabled';
    case 'reject':
      return 'cancel';
  }
};

export const RuleStatus = {
  Active: 'active',
  Disabled: 'disabled',
  Expired: 'expired',
} as const;

export type RuleStatusValue = (typeof RuleStatus)[keyof typeof RuleStatus];

export const ruleStatus = (rule: FirewallRule): RuleStatusValue => {
  if (!rule.enabled) return RuleStatus.Disabled;
  if (isExpired(rule)) return RuleStatus.Expired;
  return RuleStatus.Active;
};

/** Lower-case text a rule can be found by: its name, description, sources and destinations. */
export const ruleSearchText = (rule: FirewallRule, names: FirewallNames) =>
  [
    rule.name,
    rule.description,
    ...sourceItems(rule, names).map((item) => item.label),
    ...rule.destinations,
    ...rule.ports,
    ...rule.protocols.map(protocolName),
  ]
    .join('\n')
    .toLowerCase();
