import { useQueries } from '@tanstack/react-query';
import type { FirewallLocationPolicy, NetworkLocation } from '../../shared/api/types';
import { getFirewallLocationPolicyQueryOptions } from '../../shared/query';

export type LocationPolicies = {
  /** `undefined` while loading or after an error, `null` when nothing is enforced. */
  byLocation: Map<number, FirewallLocationPolicy | null | undefined>;
  /** Location IDs whose gateways enforce each rule, by rule ID. */
  ruleLocations: Map<number, number[]>;
  loading: boolean;
  error: boolean;
};

/** Collects the compiled policy of every location: what the gateways enforce right now. */
export const indexPolicies = (
  locations: Pick<NetworkLocation, 'id'>[],
  policies: (FirewallLocationPolicy | null | undefined)[],
) => {
  const byLocation = new Map<number, FirewallLocationPolicy | null | undefined>();
  const ruleLocations = new Map<number, number[]>();
  locations.forEach((location, index) => {
    const policy = policies[index];
    byLocation.set(location.id, policy);
    for (const rule of policy?.rules ?? []) {
      const enforcedAt = ruleLocations.get(rule.id) ?? [];
      enforcedAt.push(location.id);
      ruleLocations.set(rule.id, enforcedAt);
    }
  });
  return { byLocation, ruleLocations };
};

export const useLocationPolicies = (locations: NetworkLocation[]): LocationPolicies =>
  useQueries({
    queries: locations.map((location) =>
      getFirewallLocationPolicyQueryOptions(location.id),
    ),
    combine: (results) => ({
      ...indexPolicies(
        locations,
        results.map((result) => result.data),
      ),
      loading: results.some((result) => result.isPending),
      error: results.some((result) => result.isError),
    }),
  });
