import { describe, expect, it } from 'vitest';
import {
  duplicateRuleToForm,
  emptyForm,
  formSchema,
  formToInput,
  ruleToForm,
} from '../src/pages/FirewallPage/rule/form';
import {
  destinationItems,
  destinationsSummary,
  isExpired,
  locationItems,
  RuleStatus,
  ruleSearchText,
  ruleStatus,
  serviceItems,
  servicesSummary,
  sourceItems,
  sourcesSummary,
} from '../src/pages/FirewallPage/summary';
import type { FirewallNames } from '../src/pages/FirewallPage/useFirewallNames';
import { indexPolicies } from '../src/pages/FirewallPage/useLocationPolicies';
import type { FirewallLocationPolicy, FirewallRule } from '../src/shared/api/types';

const names: FirewallNames = {
  locations: [
    { id: 1, label: 'Office' },
    { id: 2, label: 'Cloud' },
  ],
  users: [
    { id: 1, label: 'Alice' },
    { id: 2, label: 'Bob' },
    { id: 3, label: 'Carol' },
  ],
  groups: [{ id: 7, label: 'Engineering' }],
  devices: [{ id: 9, label: 'Printer' }],
};

const rule = (overrides: Partial<FirewallRule> = {}): FirewallRule => ({
  ...formToInput(
    { ...emptyForm(), name: 'web', users: [1], destinations: '10.0.0.1' },
    null,
  ),
  id: 1,
  created_at: '2026-11-16T00:00:00',
  updated_at: '2026-11-16T00:00:00',
  ...overrides,
});

describe('firewall rule form', () => {
  it('splits addresses and ports on commas and new lines', () => {
    const input = formToInput(
      {
        ...emptyForm(),
        name: '  web ',
        users: [1],
        destinations: '10.0.0.1,\n192.168.1.0/24  10.1.0.1-10.1.0.9',
        ports: '443, 8000-8080',
        protocols: new Set([17, 6]),
      },
      null,
    );
    expect(input.name).toBe('web');
    expect(input.destinations).toEqual([
      '10.0.0.1',
      '192.168.1.0/24',
      '10.1.0.1-10.1.0.9',
    ]);
    expect(input.ports).toEqual(['443', '8000-8080']);
    expect(input.protocols).toEqual([6, 17]);
  });

  it('drops selections that an "all" toggle overrides', () => {
    const input = formToInput(
      {
        ...emptyForm(),
        name: 'x',
        all_users: true,
        users: [1, 2],
        all_locations: true,
        locations: [1],
        any_destination: true,
        destinations: '10.0.0.1',
      },
      null,
    );
    expect(input.users).toEqual([]);
    expect(input.locations).toEqual([]);
    expect(input.destinations).toEqual([]);
  });

  it('round-trips a stored rule', () => {
    const stored = rule({
      ports: ['22'],
      protocols: [6],
      expires_at: '2030-01-01T00:00:00',
    });
    const { id, created_at, updated_at, ...input } = stored;
    expect(formToInput(ruleToForm(stored), stored.expires_at)).toEqual(input);
  });

  it('duplicates a rule with a copy suffix and enabled state', () => {
    const copy = duplicateRuleToForm(rule({ name: 'SSH', enabled: false }));
    expect(copy.name).toBe('SSH (copy)');
    expect(copy.enabled).toBe(true);
  });

  it('requires a source, a destination and a location', () => {
    const result = formSchema.safeParse({
      ...emptyForm(),
      name: 'x',
      all_locations: false,
    });
    expect(result.success).toBe(false);
    const paths = result.error?.issues.map((i) => i.path.join('.'));
    expect(paths).toEqual(expect.arrayContaining(['users', 'destinations', 'locations']));
    expect(
      formSchema.safeParse({
        ...emptyForm(),
        name: 'x',
        any_source: true,
        any_destination: true,
      }).success,
    ).toBe(true);
  });
});

describe('firewall rule summaries and badges', () => {
  it('names a few selections and counts many', () => {
    expect(sourcesSummary(rule({ users: [1, 2] }), names)).toBe('Alice, Bob');
    expect(sourcesSummary(rule({ users: [1, 2, 3], groups: [7] }), names)).toMatch(
      /^3 user\(s\), Engineering$/,
    );
  });

  it('describes destinations and services', () => {
    expect(destinationsSummary(rule({ destinations: ['a', 'b', 'c', 'd', 'e'] }))).toBe(
      'a, b, c +2',
    );
    expect(servicesSummary(rule({ protocols: [6, 17], ports: ['443'] }))).toBe(
      'TCP/UDP 443',
    );
    expect(servicesSummary(rule())).toBe('Any');
  });

  it('treats stored times as UTC when checking expiry and status', () => {
    expect(isExpired(rule({ expires_at: '2000-01-01T00:00:00' }))).toBe(true);
    expect(isExpired(rule({ expires_at: '2999-01-01T00:00:00' }))).toBe(false);
    expect(isExpired(rule())).toBe(false);
    expect(ruleStatus(rule({ enabled: false }))).toBe(RuleStatus.Disabled);
    expect(ruleStatus(rule({ expires_at: '2000-01-01T00:00:00' }))).toBe(
      RuleStatus.Expired,
    );
    expect(ruleStatus(rule())).toBe(RuleStatus.Active);
  });

  it('builds structured badge items and search text', () => {
    const r = rule({
      name: 'Allow HTTPS',
      description: 'Internal apps',
      users: [1],
      groups: [7],
      destinations: ['10.0.0.0/24'],
      protocols: [6],
      ports: ['443'],
      all_locations: false,
      locations: [1, 2],
    });
    expect(sourceItems(r, names).map((i) => i.label)).toEqual(['Alice', 'Engineering']);
    expect(destinationItems(r).map((i) => i.label)).toEqual(['10.0.0.0/24']);
    expect(serviceItems(r).map((i) => i.label)).toEqual(['TCP', '443']);
    expect(locationItems(r, names).map((i) => i.label)).toEqual(['Office', 'Cloud']);
    const search = ruleSearchText(r, names);
    expect(search).toContain('allow https');
    expect(search).toContain('engineering');
    expect(search).toContain('10.0.0.0/24');
    expect(search).toContain('443');
    expect(search).toContain('tcp');
  });

  it('indexes compiled location policies by location and rule', () => {
    const policy1: FirewallLocationPolicy = {
      revision: 'rev-1',
      default_action: 'Drop',
      rules: [
        {
          id: 10,
          action: 'Accept',
          source_ranges: 2,
          destination_ranges: 1,
          protocols: [6],
          ports: ['443'],
        },
      ],
      snat_bindings: 1,
    };
    const { byLocation, ruleLocations } = indexPolicies(
      [{ id: 1 }, { id: 2 }],
      [policy1, null],
    );
    expect(byLocation.get(1)).toBe(policy1);
    expect(byLocation.get(2)).toBeNull();
    expect(ruleLocations.get(10)).toEqual([1]);
    expect(ruleLocations.get(99)).toBeUndefined();
  });
});
