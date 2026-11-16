import { createFileRoute } from '@tanstack/react-router';
import { FirewallPage } from '../../../pages/FirewallPage/FirewallPage';
import {
  getFirewallRulesQueryOptions,
  getGroupsInfoQueryOptions,
  getLocationsQueryOptions,
  getNetworkDevicesQueryOptions,
  getSnatBindingsQueryOptions,
  getUsersQueryOptions,
} from '../../../shared/query';

export const Route = createFileRoute('/_authorized/_default/firewall')({
  component: FirewallPage,
  loader: ({ context }) =>
    Promise.all([
      context.queryClient.fetchQuery(getFirewallRulesQueryOptions),
      context.queryClient.fetchQuery(getLocationsQueryOptions),
      context.queryClient.fetchQuery(getUsersQueryOptions),
      context.queryClient.fetchQuery(getGroupsInfoQueryOptions),
      context.queryClient.fetchQuery(getNetworkDevicesQueryOptions),
      context.queryClient.fetchQuery(getSnatBindingsQueryOptions),
    ]),
});
