import z from 'zod';
import { m } from '../../../paraglide/messages';
import {
  type FirewallRule,
  FirewallRuleAction,
  type FirewallRuleInput,
} from '../../../shared/api/types';
import { nameValidator } from '../../../shared/validators';

/** Protocols offered as checkboxes; anything else stays as stored. */
export const COMMON_PROTOCOLS = [6, 17, 1, 58] as const;

const splitList = (text: string | null) =>
  (text ?? '')
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);

export const formSchema = z
  .object({
    name: z.string().trim().min(1, m.form_error_required()).max(255).pipe(nameValidator),
    description: z.string().max(4096).nullable(),
    enabled: z.boolean(),
    priority: z.number(m.form_error_required()).int().min(-1_000_000).max(1_000_000),
    action: z.enum([
      FirewallRuleAction.Allow,
      FirewallRuleAction.Deny,
      FirewallRuleAction.Reject,
    ]),
    all_locations: z.boolean(),
    locations: z.array(z.number()),
    any_source: z.boolean(),
    all_users: z.boolean(),
    all_network_devices: z.boolean(),
    users: z.array(z.number()),
    groups: z.array(z.number()),
    devices: z.array(z.number()),
    any_destination: z.boolean(),
    destinations: z.string().nullable(),
    protocols: z.set(z.number()),
    ports: z.string().nullable(),
  })
  .superRefine((v, ctx) => {
    const hasSource =
      v.all_users ||
      v.all_network_devices ||
      v.users.length > 0 ||
      v.groups.length > 0 ||
      v.devices.length > 0;
    if (!v.any_source && !hasSource) {
      ctx.addIssue({
        code: 'custom',
        path: ['users'],
        message: m.firewall_error_no_source(),
      });
    }
    if (!v.any_destination && splitList(v.destinations).length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['destinations'],
        message: m.firewall_error_no_destination(),
      });
    }
    if (!v.all_locations && v.locations.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['locations'],
        message: m.firewall_error_no_location(),
      });
    }
  });

export type FormFields = z.infer<typeof formSchema>;

export const emptyForm = (): FormFields => ({
  name: '',
  description: null,
  enabled: true,
  priority: 1000,
  action: FirewallRuleAction.Allow,
  all_locations: true,
  locations: [],
  any_source: false,
  all_users: false,
  all_network_devices: false,
  users: [],
  groups: [],
  devices: [],
  any_destination: false,
  destinations: null,
  protocols: new Set(),
  ports: null,
});

export const ruleToForm = (rule: FirewallRule): FormFields => ({
  name: rule.name,
  description: rule.description || null,
  enabled: rule.enabled,
  priority: rule.priority,
  action: rule.action,
  all_locations: rule.all_locations,
  locations: rule.locations,
  any_source: rule.any_source,
  all_users: rule.all_users,
  all_network_devices: rule.all_network_devices,
  users: rule.users,
  groups: rule.groups,
  devices: rule.devices,
  any_destination: rule.any_destination,
  destinations: rule.destinations.join(', ') || null,
  protocols: new Set(rule.protocols),
  ports: rule.ports.join(', ') || null,
});

export const duplicateRuleToForm = (rule: FirewallRule): FormFields => ({
  ...ruleToForm(rule),
  name: m.firewall_duplicate_suffix({ name: rule.name }),
  enabled: true,
});

/** The payload the API takes. The server validates and canonicalises it again. */
export const formToInput = (
  value: FormFields,
  expiresAt: string | null,
): FirewallRuleInput => ({
  name: value.name.trim(),
  description: value.description ?? '',
  enabled: value.enabled,
  priority: value.priority,
  action: value.action,
  all_locations: value.all_locations,
  locations: value.all_locations ? [] : value.locations,
  any_source: value.any_source,
  all_users: value.all_users,
  all_network_devices: value.all_network_devices,
  users: value.all_users ? [] : value.users,
  groups: value.groups,
  devices: value.all_network_devices ? [] : value.devices,
  any_destination: value.any_destination,
  destinations: value.any_destination ? [] : splitList(value.destinations),
  protocols: [...value.protocols].sort((a, b) => a - b),
  ports: splitList(value.ports),
  expires_at: expiresAt,
});

export const ruleToInput = (rule: FirewallRule): FirewallRuleInput =>
  formToInput(ruleToForm(rule), rule.expires_at);
