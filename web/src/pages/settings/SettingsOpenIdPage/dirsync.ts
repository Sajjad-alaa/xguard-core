import { m } from '../../../paraglide/messages';
import type { DirectorySyncPlan } from '../../../shared/api/types';
import type { DryRunRow } from '../SettingsLdapPage/dryRun';

/** Turns a directory sync plan into rows for the dry run table. */
export const directorySyncRows = (plan: DirectorySyncPlan): DryRunRow[] => [
  ...plan.delete_users.map(({ username, reason }) => ({
    username,
    change: m.settings_openid_sync_change_deleted({ reason }),
    action: 'remove' as const,
  })),
  ...plan.disable_users.map(({ username, reason }) => ({
    username,
    change: m.settings_openid_sync_change_disabled({ reason }),
    action: 'update' as const,
  })),
  ...plan.enable_users.map(({ username, reason }) => ({
    username,
    change: m.settings_openid_sync_change_enabled({ reason }),
    action: 'update' as const,
  })),
  ...plan.create_users.map(({ username, email }) => ({
    username,
    change: m.settings_openid_sync_change_created({ email }),
    action: 'add' as const,
  })),
  ...plan.update_users.map(({ username }) => ({
    username,
    change: m.modal_ldap_dry_run_change_details(),
    action: 'update' as const,
  })),
  ...plan.link_users.map(({ username, external_id }) => ({
    username,
    change: m.settings_openid_sync_change_linked({ id: external_id }),
    action: 'update' as const,
  })),
  ...plan.remove_members.map(({ username, group }) => ({
    username,
    change: m.modal_ldap_dry_run_change_group({ group }),
    action: 'remove' as const,
  })),
  ...plan.add_members.map(({ username, group }) => ({
    username,
    change: m.modal_ldap_dry_run_change_group({ group }),
    action: 'add' as const,
  })),
];

/** Accounts a sync disables or deletes. */
export const revocationCount = (plan: DirectorySyncPlan) =>
  plan.disable_users.length + plan.delete_users.length;

/** Whether the server refused a run that needs confirmation. */
export const needsConfirmation = (message: string | undefined) =>
  !!message && message.includes('then confirm');
