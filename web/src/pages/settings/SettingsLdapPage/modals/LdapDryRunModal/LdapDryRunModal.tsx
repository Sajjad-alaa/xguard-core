import { useState } from 'react';
import { m } from '../../../../../paraglide/messages';
import type { LdapSyncReport } from '../../../../../shared/api/types';
import { Modal } from '../../../../../shared/xguard-ui/components/Modal/Modal';
import { Tabs } from '../../../../../shared/xguard-ui/components/Tabs/Tabs';
import './style.scss';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import { dryRunRows } from '../../dryRun';
import { DryRunTable } from './DryRunTable';

type Props = {
  isOpen: boolean;
  result: LdapSyncReport | null;
  onClose: () => void;
};

type DryRunTab = 'xguard' | 'ldap';

export const LdapDryRunModal = ({ isOpen, result, onClose }: Props) => {
  const [tab, setTab] = useState<DryRunTab>('xguard');

  const rows = result ? dryRunRows(result.plan) : { xguard: [], ldap: [] };
  const activeData = tab === 'xguard' ? rows.xguard : rows.ldap;
  const newGroups =
    (tab === 'xguard'
      ? result?.plan.create_local_groups
      : result?.plan.create_remote_groups) ?? [];
  const skipped = result?.plan.skipped ?? [];

  return (
    <Modal
      title={m.modal_ldap_dry_run_title()}
      size="primary"
      isOpen={isOpen}
      onClose={onClose}
      contentClassName="ldap-dry-run-modal"
    >
      <p className="description">{m.modal_ldap_dry_run_description()}</p>
      <SizedBox height={ThemeSpacing.Xl} />
      <Tabs
        items={[
          {
            title: m.modal_ldap_dry_run_tab_xguard(),
            active: tab === 'xguard',
            onClick: () => setTab('xguard'),
          },
          {
            title: m.modal_ldap_dry_run_tab_ldap(),
            active: tab === 'ldap',
            onClick: () => setTab('ldap'),
          },
        ]}
      />
      {newGroups.length > 0 && (
        <p className="description">
          {m.modal_ldap_dry_run_new_groups({ groups: newGroups.join(', ') })}
        </p>
      )}
      <DryRunTable key={tab} data={activeData} />
      {skipped.length > 0 && (
        <>
          <SizedBox height={ThemeSpacing.Xl} />
          <p className="description">{m.modal_ldap_dry_run_skipped()}</p>
          <ul className="skipped">
            {skipped.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      )}
    </Modal>
  );
};
