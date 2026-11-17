import { m } from '../../../../paraglide/messages';
import type { DirectorySyncReport } from '../../../../shared/api/types';
import { Modal } from '../../../../shared/xguard-ui/components/Modal/Modal';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { DryRunTable } from '../../SettingsLdapPage/modals/LdapDryRunModal/DryRunTable';
import '../../SettingsLdapPage/modals/LdapDryRunModal/style.scss';
import { directorySyncRows } from '../dirsync';

type Props = {
  isOpen: boolean;
  result: DirectorySyncReport | null;
  onClose: () => void;
};

export const DirectorySyncDryRunModal = ({ isOpen, result, onClose }: Props) => {
  const plan = result?.plan;
  const rows = plan ? directorySyncRows(plan) : [];
  const notes = [...(plan?.skipped ?? []), ...(result?.errors ?? [])];

  return (
    <Modal
      title={
        result?.applied
          ? m.settings_openid_sync_result_title()
          : m.settings_openid_sync_dry_run_title()
      }
      size="primary"
      isOpen={isOpen}
      onClose={onClose}
      contentClassName="ldap-dry-run-modal"
    >
      <p className="description">
        {result?.applied
          ? m.settings_openid_sync_result_description()
          : m.settings_openid_sync_dry_run_description()}
      </p>
      {plan && (
        <p className="description">
          {m.settings_openid_sync_stats({
            users: plan.stats.directory_users,
            scope: plan.stats.directory_users_in_scope,
            matched: plan.stats.matched_users,
            groups: plan.stats.synced_groups,
          })}
        </p>
      )}
      {plan && plan.create_groups.length > 0 && (
        <p className="description">
          {m.modal_ldap_dry_run_new_groups({ groups: plan.create_groups.join(', ') })}
        </p>
      )}
      <SizedBox height={ThemeSpacing.Md} />
      <DryRunTable data={rows} />
      {notes.length > 0 && (
        <>
          <SizedBox height={ThemeSpacing.Xl} />
          <p className="description">{m.modal_ldap_dry_run_skipped()}</p>
          <ul className="skipped">
            {notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      )}
    </Modal>
  );
};
