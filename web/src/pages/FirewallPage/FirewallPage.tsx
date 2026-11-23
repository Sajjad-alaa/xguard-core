import './style.scss';
import { useSuspenseQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { useCallback, useMemo } from 'react';
import { m } from '../../paraglide/messages';
import { Page } from '../../shared/components/Page/Page';
import { TablePageLayout } from '../../shared/layout/TablePageLayout/TablePageLayout';
import {
  getFirewallRulesQueryOptions,
  getLocationsQueryOptions,
  getSnatBindingsQueryOptions,
} from '../../shared/query';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Tabs } from '../../shared/xguard-ui/components/Tabs/Tabs';
import type { TabsItem } from '../../shared/xguard-ui/components/Tabs/types';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { EnforcementTable } from './EnforcementTable';
import { FirewallRulesTable } from './FirewallRulesTable';
import { CESnatBindingModal } from './modals/CESnatBindingModal';
import { SnatTable } from './SnatTable';
import { FirewallPageTab, type FirewallPageTabValue } from './tabs';
import { useFirewallNames } from './useFirewallNames';
import { useLocationPolicies } from './useLocationPolicies';

export const FirewallPage = () => {
  const navigate = useNavigate();
  const { tab } = useSearch({ from: '/_authorized/_default/firewall/' });
  const activeTab: FirewallPageTabValue = tab ?? FirewallPageTab.Rules;

  const { data: rules } = useSuspenseQuery(getFirewallRulesQueryOptions);
  const { data: snat } = useSuspenseQuery(getSnatBindingsQueryOptions);
  const { data: locations } = useSuspenseQuery(getLocationsQueryOptions);
  const names = useFirewallNames();
  const policies = useLocationPolicies(locations);

  const selectTab = useCallback(
    (next: FirewallPageTabValue) => {
      navigate({
        to: '/firewall',
        search: next === FirewallPageTab.Rules ? {} : { tab: next },
        replace: true,
      });
    },
    [navigate],
  );

  const tabs = useMemo(
    (): TabsItem[] => [
      {
        title: m.firewall_tab_rules(),
        active: activeTab === FirewallPageTab.Rules,
        onClick: () => selectTab(FirewallPageTab.Rules),
      },
      {
        title: m.firewall_tab_snat(),
        active: activeTab === FirewallPageTab.Snat,
        onClick: () => selectTab(FirewallPageTab.Snat),
      },
      {
        title: m.firewall_tab_enforcement(),
        active: activeTab === FirewallPageTab.Enforcement,
        onClick: () => selectTab(FirewallPageTab.Enforcement),
      },
    ],
    [activeTab, selectTab],
  );

  return (
    <>
      <Page id="firewall-page" title={m.firewall_title()}>
        <SizedBox height={ThemeSpacing.Md} />
        <Tabs items={tabs} />
        <SizedBox height={ThemeSpacing.Xl2} />
        <TablePageLayout>
          {activeTab === FirewallPageTab.Rules && (
            <FirewallRulesTable rules={rules} names={names} policies={policies} />
          )}
          {activeTab === FirewallPageTab.Snat && (
            <SnatTable bindings={snat} names={names} />
          )}
          {activeTab === FirewallPageTab.Enforcement && (
            <EnforcementTable locations={locations} policies={policies} />
          )}
        </TablePageLayout>
      </Page>
      <CESnatBindingModal names={names} />
    </>
  );
};
