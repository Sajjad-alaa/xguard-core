import { m } from '../../../paraglide/messages';
import type { LdapSyncPlan } from '../../../shared/api/types';

export type DryRunAction = 'add' | 'remove' | 'update';

export interface DryRunRow {
  username: string;
  change: string;
  action: DryRunAction;
}

export interface DryRunRows {
  xguard: DryRunRow[];
  ldap: DryRunRow[];
}

const side = (
  created: string[],
  updated: string[],
  deleted: string[],
  status: LdapSyncPlan['local_status'],
  added: LdapSyncPlan['add_local_members'],
  removed: LdapSyncPlan['remove_local_members'],
): DryRunRow[] => [
  ...deleted.map((username) => ({
    username,
    change: m.modal_ldap_dry_run_change_account(),
    action: 'remove' as const,
  })),
  ...created.map((username) => ({
    username,
    change: m.modal_ldap_dry_run_change_account(),
    action: 'add' as const,
  })),
  ...updated.map((username) => ({
    username,
    change: m.modal_ldap_dry_run_change_details(),
    action: 'update' as const,
  })),
  ...status.map(({ username, active }) => ({
    username,
    change: active
      ? m.modal_ldap_dry_run_change_enabled()
      : m.modal_ldap_dry_run_change_disabled(),
    action: 'update' as const,
  })),
  ...removed.map(({ username, group }) => ({
    username,
    change: m.modal_ldap_dry_run_change_group({ group }),
    action: 'remove' as const,
  })),
  ...added.map(({ username, group }) => ({
    username,
    change: m.modal_ldap_dry_run_change_group({ group }),
    action: 'add' as const,
  })),
];

/** Turns a sync plan into one table per system. */
export const dryRunRows = (plan: LdapSyncPlan): DryRunRows => ({
  xguard: side(
    plan.create_local,
    plan.update_local,
    plan.delete_local,
    plan.local_status,
    plan.add_local_members,
    plan.remove_local_members,
  ),
  ldap: side(
    plan.create_remote,
    plan.update_remote,
    plan.delete_remote,
    plan.remote_status,
    plan.add_remote_members,
    plan.remove_remote_members,
  ),
});

export const deletionCount = (plan: LdapSyncPlan) =>
  plan.delete_local.length + plan.delete_remote.length;
