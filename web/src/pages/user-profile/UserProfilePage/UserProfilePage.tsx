import './style.scss';
import { useSuspenseQuery } from '@tanstack/react-query';
import { useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useCallback, useEffect, useMemo, useRef } from 'react';
import { titleCase } from 'text-case';
import { m } from '../../../paraglide/messages';
import type { ApiToken } from '../../../shared/api/types';
import { Page } from '../../../shared/components/Page/Page';
import { useAuth } from '../../../shared/hooks/useAuth';
import {
  getUserAuthKeysQueryOptions,
  userProfileQueryOptions,
} from '../../../shared/query';
import { Tabs } from '../../../shared/xguard-ui/components/Tabs/Tabs';
import type { TabsItem } from '../../../shared/xguard-ui/components/Tabs/types';
import { createUserProfileStore, UserProfileContext } from './hooks/useUserProfilePage';
import { ProfileAuthKeysTab } from './tabs/ProfileAuthKeysTab/ProfileAuthKeysTab';
import { ProfileDetailsTab } from './tabs/ProfileDetailsTab/ProfileDetailsTab';
import { ProfileDevicesTab } from './tabs/ProfileDevicesTab/ProfileDevicesTab';
import {
  ApiTokensTabAvailability,
  type ApiTokensTabAvailabilityValue,
  UserProfileTab,
  type UserProfileTabValue,
} from './tabs/types';

const defaultTab = UserProfileTab.Details;

// API tokens are not part of XGuard yet (stable empty list for hook deps).
const NO_API_TOKENS: ApiToken[] = [];
export const UserProfilePage = () => {
  const navigate = useNavigate();
  const authUsername = useAuth((s) => s.user?.username as string);
  const search = useSearch({ from: '/_authorized/_default/user/$username' });
  const activeTab = search.tab ?? defaultTab;

  const { username } = useParams({
    from: '/_authorized/_default/user/$username',
  });

  const isSelf = useMemo(
    (): boolean => authUsername === username,
    [authUsername, username],
  );

  const { data: userProfile } = useSuspenseQuery(userProfileQueryOptions(username));
  const { data: userAuthKeys } = useSuspenseQuery(getUserAuthKeysQueryOptions(username));

  // API tokens are not part of XGuard yet (enterprise code removed); the tab stays hidden.
  const apiTokensTabAvailability: ApiTokensTabAvailabilityValue =
    ApiTokensTabAvailability.Hidden;

  const userApiTokens = NO_API_TOKENS;

  const pageTitle = useMemo(() => {
    if (isSelf) {
      return m.profile_my_profile();
    }
    const name = titleCase(
      `${userProfile.user.first_name} ${userProfile.user.last_name}`,
    );
    return m.profile_title({
      name,
    });
  }, [isSelf, userProfile.user.first_name, userProfile.user.last_name]);

  const store = useRef(
    createUserProfileStore({
      profile: userProfile,
      authKeys: userAuthKeys,
      apiTokens: userApiTokens ?? [],
    }),
  ).current;

  const setActiveTab = useCallback(
    (tab: UserProfileTabValue) => {
      navigate({
        from: '/user/$username',
        to: '/user/$username',
        search: (perv) => ({ ...perv, tab }),
      });
    },
    [navigate],
  );

  const setApiTokensTabIfAllowed = useCallback(() => {
    if (apiTokensTabAvailability === ApiTokensTabAvailability.Hidden) {
      return;
    }

    setActiveTab(UserProfileTab.ApiTokens);
  }, [setActiveTab]);

  const tabsConfiguration = useMemo(() => {
    const res: TabsItem[] = [
      {
        title: m.profile_tabs_details(),
        active: activeTab === UserProfileTab.Details,
        onClick: () => setActiveTab(UserProfileTab.Details),
      },
      {
        title: m.profile_tabs_devices(),
        active: activeTab === UserProfileTab.Devices,
        onClick: () => setActiveTab(UserProfileTab.Devices),
      },
      {
        title: m.profile_tabs_auth_keys(),
        active: activeTab === UserProfileTab.AuthKeys,
        onClick: () => setActiveTab(UserProfileTab.AuthKeys),
      },
      {
        title: m.profile_tabs_api(),
        active: activeTab === UserProfileTab.ApiTokens,
        hidden: apiTokensTabAvailability === ApiTokensTabAvailability.Hidden,
        onClick: setApiTokensTabIfAllowed,
      },
    ];
    return res;
  }, [setActiveTab, setApiTokensTabIfAllowed, activeTab]);

  const activeTabContent = useMemo(() => {
    switch (activeTab) {
      case UserProfileTab.Details:
        return <ProfileDetailsTab />;
      case UserProfileTab.Devices:
        return <ProfileDevicesTab />;
      case UserProfileTab.AuthKeys:
        return <ProfileAuthKeysTab />;
      case UserProfileTab.ApiTokens:
        return null;
      default:
        return <ProfileDetailsTab />;
    }
  }, [activeTab]);

  useEffect(() => {
    if (
      activeTab !== UserProfileTab.ApiTokens ||
      apiTokensTabAvailability !== ApiTokensTabAvailability.Hidden
    ) {
      return;
    }

    navigate({
      from: '/user/$username',
      search: {
        tab: UserProfileTab.Details,
      },
    });
  }, [activeTab, navigate]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: side effect
  useEffect(() => {
    if (store && userProfile) {
      store.setState({
        ...userProfile,
      });
    }
  }, [userProfile]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: side effect
  useEffect(() => {
    if (store && userAuthKeys) {
      store.setState({
        authKeys: userAuthKeys,
      });
    }
  }, [userAuthKeys]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: side effect
  useEffect(() => {
    if (store && userApiTokens) {
      store.setState({
        apiTokens: userApiTokens,
      });
    }
  }, [userApiTokens]);

  return (
    <UserProfileContext value={store}>
      <Page id="user-profile-page" title={pageTitle}>
        <Tabs items={tabsConfiguration} />
        {activeTabContent}
      </Page>
    </UserProfileContext>
  );
};
