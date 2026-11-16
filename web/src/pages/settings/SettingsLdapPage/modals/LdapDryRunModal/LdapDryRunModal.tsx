import { useState } from 'react';
import { m } from '../../../../../paraglide/messages';
import type { LdapDryRunResult } from '../../../../../shared/api/types';
import { Modal } from '../../../../../shared/xguard-ui/components/Modal/Modal';
import { Tabs } from '../../../../../shared/xguard-ui/components/Tabs/Tabs';
import './style.scss';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import { DryRunTable } from './DryRunTable';

type Props = {
  isOpen: boolean;
  result: LdapDryRunResult | null;
  onClose: () => void;
};

type DryRunTab = 'xguard' | 'ldap';

export const LdapDryRunModal = ({ isOpen, result, onClose }: Props) => {
  const [tab, setTab] = useState<DryRunTab>('xguard');

  const activeData = (tab === 'xguard' ? result?.xguard : result?.ldap) ?? [];

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
      <DryRunTable key={tab} data={activeData} />
    </Modal>
  );
};
