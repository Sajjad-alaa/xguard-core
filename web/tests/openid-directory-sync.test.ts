import { describe, expect, it } from 'vitest';
import {
  directorySyncRows,
  needsConfirmation,
  revocationCount,
} from '../src/pages/settings/SettingsOpenIdPage/dirsync';
import {
  directorySecretStored,
  formSchema,
  supportsDirectorySync,
  toForm,
  toInput,
} from '../src/pages/settings/SettingsOpenIdPage/form';
import type { DirectorySyncPlan, ExternalOpenIdProvider } from '../src/shared/api/types';

const okta: ExternalOpenIdProvider = {
  id: 1,
  kind: 'Okta',
  issuer: 'https://example.okta.com',
  client_id: 'sign-in',
  enabled: true,
  display_name: null,
  disable_password_management: false,
  client_secret_set: true,
  directory_sync_enabled: true,
  directory_sync_interval: 300,
  directory_sync_user_behavior: 'disable',
  directory_sync_admin_behavior: 'keep',
  directory_sync_target: 'all',
  directory_sync_group_match: ['Eng*', 'Sales'],
  directory_sync_user_groups: [],
  prefetch_users: true,
  admin_email: null,
  google_service_account_email: null,
  google_service_account_key_set: false,
  okta_dirsync_client_id: 'sync-app',
  okta_private_jwk_set: true,
  jumpcloud_api_key_set: false,
};

const emptyPlan = (): DirectorySyncPlan => ({
  link_users: [],
  create_users: [],
  update_users: [],
  enable_users: [],
  disable_users: [],
  delete_users: [],
  create_groups: [],
  add_members: [],
  remove_members: [],
  skipped: [],
  stats: {
    directory_users: 0,
    directory_users_in_scope: 0,
    directory_groups: 0,
    synced_groups: 0,
    matched_users: 0,
    linked_users: 0,
  },
});

describe('OpenID directory sync form', () => {
  it('round-trips the settings and keeps stored secrets', () => {
    const form = toForm(okta, false);
    expect(form.directory_sync_group_match).toBe('Eng*, Sales');
    expect(form.okta_private_jwk).toBe('');
    const input = toInput(form);
    expect(input.directory_sync_group_match).toEqual(['Eng*', 'Sales']);
    expect(input.directory_sync_user_groups).toEqual([]);
    expect(input.okta_private_jwk).toBeUndefined();
    expect(input.jumpcloud_api_key).toBeUndefined();
    expect(input.okta_dirsync_client_id).toBe('sync-app');
    expect(
      toInput({ ...form, okta_private_jwk: ' {"kty":"RSA"} ' }).okta_private_jwk,
    ).toBe('{"kty":"RSA"}');
    expect(formSchema.safeParse(form).success).toBe(true);
    expect(directorySecretStored(okta, 'Okta')).toBe(true);
    expect(directorySecretStored(okta, 'JumpCloud')).toBe(false);
  });

  it('checks the directory sync fields', () => {
    const form = toForm(okta, false);
    expect(formSchema.safeParse({ ...form, directory_sync_interval: 30 }).success).toBe(
      false,
    );
    expect(formSchema.safeParse({ ...form, okta_dirsync_client_id: '' }).success).toBe(
      false,
    );
    // Turned off, nothing about the sync is required.
    expect(
      formSchema.safeParse({
        ...form,
        directory_sync_enabled: false,
        okta_dirsync_client_id: '',
        directory_sync_interval: 30,
      }).success,
    ).toBe(true);
    expect(
      formSchema.safeParse({ ...form, kind: 'Google', admin_email: '' }).success,
    ).toBe(false);
    expect(formSchema.safeParse({ ...form, kind: 'Custom' }).success).toBe(false);
    expect(supportsDirectorySync('Zitadel')).toBe(false);
    expect(supportsDirectorySync('Microsoft')).toBe(true);
  });
});

describe('OpenID directory sync dry run', () => {
  it('lists every change, removals first', () => {
    const plan: DirectorySyncPlan = {
      ...emptyPlan(),
      create_users: [
        {
          username: 'alice',
          email: 'alice@example.org',
          first_name: 'Alice',
          last_name: 'A',
          external_id: 'u1',
        },
      ],
      disable_users: [{ username: 'bob', reason: 'disabled in the directory' }],
      delete_users: [{ username: 'carol', reason: 'missing from the directory' }],
      link_users: [{ username: 'dave', external_id: 'u4' }],
      add_members: [{ group: 'Sales', username: 'alice' }],
      remove_members: [{ group: 'Engineering', username: 'dave' }],
    };
    const rows = directorySyncRows(plan);
    expect(rows.map((row) => [row.username, row.action])).toEqual([
      ['carol', 'remove'],
      ['bob', 'update'],
      ['alice', 'add'],
      ['dave', 'update'],
      ['dave', 'remove'],
      ['alice', 'add'],
    ]);
    expect(rows[0].change).toContain('missing from the directory');
    expect(rows[5].change).toContain('Sales');
    expect(revocationCount(plan)).toBe(2);
    expect(directorySyncRows(emptyPlan())).toEqual([]);
  });

  it('recognizes runs that need confirmation', () => {
    expect(
      needsConfirmation(
        'The sync would disable or delete 9 accounts. Check the settings with a dry run, then confirm.',
      ),
    ).toBe(true);
    expect(needsConfirmation('The directory refused XGuard credentials')).toBe(false);
    expect(needsConfirmation(undefined)).toBe(false);
  });
});
