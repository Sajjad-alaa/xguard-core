import { useNavigate, useSearch } from '@tanstack/react-router';
import { type JSX, useMemo } from 'react';
import { m } from '../../../paraglide/messages';
import { Page } from '../../../shared/components/Page/Page';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Tabs } from '../../../shared/xguard-ui/components/Tabs/Tabs';
import type { TabProps } from '../../../shared/xguard-ui/components/Tabs/types';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { SettingsCertificatesTab } from './tabs/SettingsCertificatesTab/SettingsCertificatesTab';
import { SettingsGeneralTab } from './tabs/SettingsGeneralTab';
import { SettingsNotificationsTab } from './tabs/SettingsNotificationsTab';
import { type SettingsTabValue, settingsTabsSchema } from './types';
import { useCertificatesWarningState } from './useCertificatesWarningState';

const tabComponent: Record<SettingsTabValue, JSX.Element> = {
  general: <SettingsGeneralTab />,
  notifications: <SettingsNotificationsTab />,
  certs: <SettingsCertificatesTab />,
};

const tabToTitle = (tab: SettingsTabValue): string => {
  switch (tab) {
    case 'general':
      return m.settings_tab_general();
    case 'notifications':
      return m.settings_tab_notifications();
    case 'certs':
      return m.settings_tab_certificates();
  }
};

export const SettingsIndexPage = () => {
  const navigateTab = useNavigate({ from: '/settings/' });
  const search = useSearch({ from: '/_authorized/_default/settings/' });
  const certificateWarningState = useCertificatesWarningState();

  const tabs: TabProps[] = useMemo(
    () =>
      settingsTabsSchema.options.map(
        (tab): TabProps => ({
          title: tabToTitle(tab),
          active: search.tab === tab,
          icon: tab === 'certs' ? certificateWarningState.tabIcon : undefined,
          iconColor: tab === 'certs' ? certificateWarningState.tabIconColor : undefined,
          onClick: () => {
            navigateTab({ search: { tab } });
          },
        }),
      ),
    [
      certificateWarningState.tabIcon,
      certificateWarningState.tabIconColor,
      navigateTab,
      search.tab,
    ],
  );

  return (
    <Page id="settings-index-page" title={m.settings_page_title()}>
      <SizedBox height={ThemeSpacing.Md} />
      <Tabs items={tabs} />
      {tabComponent[search.tab]}
    </Page>
  );
};
