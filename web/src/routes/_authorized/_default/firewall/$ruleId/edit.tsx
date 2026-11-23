import { createFileRoute, notFound } from '@tanstack/react-router';
import { FirewallRulePage } from '../../../../../pages/FirewallPage/rule/FirewallRulePage';
import {
  getFirewallRulesQueryOptions,
  getGroupsInfoQueryOptions,
  getLocationsQueryOptions,
  getNetworkDevicesQueryOptions,
  getUsersQueryOptions,
} from '../../../../../shared/query';

export const Route = createFileRoute('/_authorized/_default/firewall/$ruleId/edit')({
  loader: async ({ context, params }) => {
    const id = Number(params.ruleId);
    if (!Number.isSafeInteger(id) || id <= 0) throw notFound();
    await Promise.all([
      context.queryClient.fetchQuery(getFirewallRulesQueryOptions),
      context.queryClient.fetchQuery(getLocationsQueryOptions),
      context.queryClient.fetchQuery(getUsersQueryOptions),
      context.queryClient.fetchQuery(getGroupsInfoQueryOptions),
      context.queryClient.fetchQuery(getNetworkDevicesQueryOptions),
    ]);
    return id;
  },
  component: RouteComponent,
});

function RouteComponent() {
  const ruleId = Route.useLoaderData();
  return <FirewallRulePage ruleId={ruleId} />;
}
