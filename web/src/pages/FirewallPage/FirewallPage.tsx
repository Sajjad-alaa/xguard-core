import { useSuspenseQuery } from '@tanstack/react-query';
import { m } from '../../paraglide/messages';
import { Page } from '../../shared/components/Page/Page';
import { TablePageLayout } from '../../shared/layout/TablePageLayout/TablePageLayout';
import {
  getFirewallRulesQueryOptions,
  getSnatBindingsQueryOptions,
} from '../../shared/query';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { FirewallRulesTable } from './FirewallRulesTable';
import { CEFirewallRuleModal } from './modals/CEFirewallRuleModal/CEFirewallRuleModal';
import { CESnatBindingModal } from './modals/CESnatBindingModal';
import { SnatTable } from './SnatTable';
import { useFirewallNames } from './useFirewallNames';

export const FirewallPage = () => {
  const { data: rules } = useSuspenseQuery(getFirewallRulesQueryOptions);
  const { data: snat } = useSuspenseQuery(getSnatBindingsQueryOptions);
  const names = useFirewallNames();

  return (
    <>
      <Page id="firewall-page" title={m.firewall_title()}>
        <SizedBox height={ThemeSpacing.Xl3} />
        <TablePageLayout>
          <FirewallRulesTable rules={rules} names={names} />
          <SizedBox height={ThemeSpacing.Xl3} />
          <SnatTable bindings={snat} names={names} />
        </TablePageLayout>
      </Page>
      <CEFirewallRuleModal names={names} />
      <CESnatBindingModal names={names} />
    </>
  );
};
