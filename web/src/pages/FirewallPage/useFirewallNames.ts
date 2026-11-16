import { useSuspenseQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import {
  getGroupsInfoQueryOptions,
  getLocationsQueryOptions,
  getNetworkDevicesQueryOptions,
  getUsersQueryOptions,
} from '../../shared/query';

export type NamedItem = { id: number; label: string };

/** Everything a rule can refer to, for pickers and for showing names instead of IDs. */
export type FirewallNames = {
  locations: NamedItem[];
  users: NamedItem[];
  groups: NamedItem[];
  devices: NamedItem[];
};

export const useFirewallNames = (): FirewallNames => {
  const { data: locations } = useSuspenseQuery(getLocationsQueryOptions);
  const { data: users } = useSuspenseQuery(getUsersQueryOptions);
  const { data: groups } = useSuspenseQuery(getGroupsInfoQueryOptions);
  const { data: devices } = useSuspenseQuery(getNetworkDevicesQueryOptions);

  return useMemo(
    () => ({
      locations: locations.map((l) => ({ id: l.id, label: l.name })),
      users: users.map((u) => ({
        id: u.id,
        label: `${u.first_name} ${u.last_name} (${u.username})`,
      })),
      groups: groups.map((g) => ({ id: g.id, label: g.name })),
      devices: devices.map((d) => ({ id: d.id, label: d.name })),
    }),
    [locations, users, groups, devices],
  );
};
