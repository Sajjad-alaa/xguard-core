import { Link } from '@tanstack/react-router';
import {
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../paraglide/messages';
import type {
  FirewallLocationPolicy,
  FirewallPolicyAction,
  NetworkLocation,
} from '../../shared/api/types';
import { Badge } from '../../shared/xguard-ui/components/Badge/Badge';
import { EmptyStateFlexible } from '../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import { TableBody } from '../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../shared/xguard-ui/components/table/TableCell/TableCell';
import { TableTop } from '../../shared/xguard-ui/components/table/TableTop/TableTop';
import type { LocationPolicies } from './useLocationPolicies';

const columnHelper = createColumnHelper<NetworkLocation>();

const defaultActionBadge = (
  policy: FirewallLocationPolicy | null | undefined,
  loading: boolean,
  error: boolean,
) => {
  if (loading) return <Skeleton width={96} height={20} />;
  if (error || policy === undefined) {
    return (
      <Badge
        variant="warning"
        showIcon
        icon="warning-filled"
        text={m.firewall_enforcement_unavailable()}
      />
    );
  }
  if (policy === null) {
    return <Badge variant="neutral" text={m.firewall_enforcement_off()} />;
  }
  if (policy.default_action === null) {
    return <Badge variant="neutral" text={m.firewall_enforcement_snat_only()} />;
  }
  const map: Record<
    FirewallPolicyAction,
    {
      variant: 'success' | 'critical';
      icon: 'check-circle' | 'disabled' | 'cancel';
      label: string;
    }
  > = {
    Accept: {
      variant: 'success',
      icon: 'check-circle',
      label: m.firewall_enforcement_default_accept(),
    },
    Drop: {
      variant: 'critical',
      icon: 'disabled',
      label: m.firewall_enforcement_default_drop(),
    },
    Reject: {
      variant: 'critical',
      icon: 'cancel',
      label: m.firewall_enforcement_default_reject(),
    },
  };
  const cfg = map[policy.default_action];
  return <Badge variant={cfg.variant} showIcon icon={cfg.icon} text={cfg.label} />;
};

type Props = {
  locations: NetworkLocation[];
  policies: LocationPolicies;
};

export const EnforcementTable = ({ locations, policies }: Props) => {
  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: m.firewall_enforcement_col_location(),
        minSize: 220,
        enableSorting: true,
        meta: { flex: true },
        cell: (info) => {
          const location = info.row.original;
          return (
            <TableCell>
              <Link
                className="location-link"
                to="/locations/$locationId/edit"
                params={{ locationId: String(location.id) }}
              >
                {location.name}
              </Link>
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'default_action',
        header: m.firewall_enforcement_col_default(),
        size: 180,
        minSize: 150,
        cell: (info) => (
          <TableCell>
            {defaultActionBadge(
              policies.byLocation.get(info.row.original.id),
              policies.loading,
              policies.error,
            )}
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'rules_count',
        header: m.firewall_enforcement_col_rules(),
        size: 160,
        minSize: 130,
        cell: (info) => {
          if (policies.loading) {
            return (
              <TableCell>
                <Skeleton width={40} height={18} />
              </TableCell>
            );
          }
          const policy = policies.byLocation.get(info.row.original.id);
          return (
            <TableCell>
              <span className="rule-order">{policy ? policy.rules.length : '—'}</span>
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'snat_count',
        header: m.firewall_enforcement_col_snat(),
        size: 160,
        minSize: 130,
        cell: (info) => {
          if (policies.loading) {
            return (
              <TableCell>
                <Skeleton width={40} height={18} />
              </TableCell>
            );
          }
          const policy = policies.byLocation.get(info.row.original.id);
          return (
            <TableCell>
              <span className="rule-order">{policy ? policy.snat_bindings : '—'}</span>
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'revision',
        header: m.firewall_enforcement_col_revision(),
        size: 200,
        minSize: 160,
        cell: (info) => {
          if (policies.loading) {
            return (
              <TableCell>
                <Skeleton width={110} height={18} />
              </TableCell>
            );
          }
          const policy = policies.byLocation.get(info.row.original.id);
          return (
            <TableCell>
              {policy?.revision ? (
                <Badge
                  variant="outlined"
                  text={policy.revision.slice(0, 12)}
                  title={policy.revision}
                />
              ) : (
                <span className="muted">—</span>
              )}
            </TableCell>
          );
        },
      }),
    ],
    [policies],
  );

  const table = useReactTable({
    initialState: { sorting: [{ id: 'name', desc: false }] },
    columns,
    data: locations,
    getRowId: (loc) => String(loc.id),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
  });

  if (locations.length === 0) {
    return (
      <EmptyStateFlexible
        icon="gateway"
        title={m.firewall_enforcement_empty_title()}
        subtitle={m.firewall_enforcement_empty_subtitle()}
      />
    );
  }

  return (
    <>
      <TableTop text={m.firewall_enforcement_title()} />
      <TableBody table={table} />
    </>
  );
};
