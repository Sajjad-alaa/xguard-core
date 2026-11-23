import { createFileRoute } from '@tanstack/react-router';
import z from 'zod';
import { FirewallPage } from '../../../../pages/FirewallPage/FirewallPage';
import { FirewallPageTab } from '../../../../pages/FirewallPage/tabs';
import {
  getFirewallRulesQueryOptions,
  getGroupsInfoQueryOptions,
  getLocationsQueryOptions,
  getNetworkDevicesQueryOptions,
  getSnatBindingsQueryOptions,
  getUsersQueryOptions,
} from '../../../../shared/query';

const searchSchema = z.object({
  tab: z.enum(FirewallPageTab).optional().catch(undefined),
});

export const Route = createFileRoute('/_authorized/_default/firewall/')({
  validateSearch: searchSchema,
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
