import { describe, expect, it } from 'vitest';
import { deletionCount, dryRunRows } from '../src/pages/settings/SettingsLdapPage/dryRun';
import type { LdapSyncPlan } from '../src/shared/api/types';

const emptyPlan = (): LdapSyncPlan => ({
  create_local: [],
  update_local: [],
  delete_local: [],
  local_status: [],
  create_local_groups: [],
  add_local_members: [],
  remove_local_members: [],
  create_remote: [],
  update_remote: [],
  delete_remote: [],
  remote_status: [],
  create_remote_groups: [],
  add_remote_members: [],
  remove_remote_members: [],
  skipped: [],
});

describe('LDAP dry run', () => {
  it('lists each side separately', () => {
    const plan: LdapSyncPlan = {
      ...emptyPlan(),
      create_local: ['alice'],
      delete_local: ['bob'],
      local_status: [{ username: 'carol', active: false }],
      add_local_members: [{ group: 'vpn', username: 'alice' }],
      update_remote: ['dave'],
    };
    const rows = dryRunRows(plan);
    expect(rows.xguard.map((row) => [row.username, row.action])).toEqual([
      ['bob', 'remove'],
      ['alice', 'add'],
      ['carol', 'update'],
      ['alice', 'add'],
    ]);
    expect(rows.xguard[3].change).toContain('vpn');
    expect(rows.ldap).toEqual([
      expect.objectContaining({ username: 'dave', action: 'update' }),
    ]);
  });

  it('counts deletions on both sides', () => {
    expect(
      deletionCount({ ...emptyPlan(), delete_local: ['a'], delete_remote: ['b', 'c'] }),
    ).toBe(3);
    expect(dryRunRows(emptyPlan())).toEqual({ xguard: [], ldap: [] });
  });
});
