import { createFileRoute } from '@tanstack/react-router';
import z from 'zod';
import { FirewallRulePage } from '../../../../pages/FirewallPage/rule/FirewallRulePage';
import {
  getFirewallRulesQueryOptions,
  getGroupsInfoQueryOptions,
  getLocationsQueryOptions,
  getNetworkDevicesQueryOptions,
  getUsersQueryOptions,
} from '../../../../shared/query';

const searchSchema = z.object({
  /** Start from a copy of this rule. */
  duplicate: z.number().int().positive().optional().catch(undefined),
});

export const Route = createFileRoute('/_authorized/_default/firewall/add-rule')({
  validateSearch: searchSchema,
  loader: ({ context }) =>
    Promise.all([
      context.queryClient.fetchQuery(getFirewallRulesQueryOptions),
      context.queryClient.fetchQuery(getLocationsQueryOptions),
      context.queryClient.fetchQuery(getUsersQueryOptions),
      context.queryClient.fetchQuery(getGroupsInfoQueryOptions),
      context.queryClient.fetchQuery(getNetworkDevicesQueryOptions),
    ]),
  component: RouteComponent,
});

function RouteComponent() {
  const { duplicate } = Route.useSearch();
  return <FirewallRulePage duplicateOf={duplicate} />;
}
