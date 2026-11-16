import {
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo, useState } from 'react';
import { m } from '../../../../../paraglide/messages';
import { Badge } from '../../../../../shared/xguard-ui/components/Badge/Badge';
import { BadgeVariant } from '../../../../../shared/xguard-ui/components/Badge/types';
import { EmptyState } from '../../../../../shared/xguard-ui/components/EmptyState/EmptyState';
import { Search } from '../../../../../shared/xguard-ui/components/Search/Search';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { TableBody } from '../../../../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../../../../shared/xguard-ui/components/table/TableCell/TableCell';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import type { DryRunAction, DryRunRow } from '../../dryRun';

const columnHelper = createColumnHelper<DryRunRow>();

const statusBadge = (action: DryRunAction) => {
  switch (action) {
    case 'add':
      return { variant: BadgeVariant.Success, text: m.modal_ldap_dry_run_status_added() };
    case 'remove':
      return {
        variant: BadgeVariant.Critical,
        text: m.modal_ldap_dry_run_status_removed(),
      };
    case 'update':
      return {
        variant: BadgeVariant.Warning,
        text: m.modal_ldap_dry_run_status_updated(),
      };
  }
};

const textCell = (info: { getValue: () => string }) => (
  <TableCell>
    <span>{info.getValue()}</span>
  </TableCell>
);

export const DryRunTable = ({ data }: { data: DryRunRow[] }) => {
  const [search, setSearch] = useState('');

  const columns = useMemo(
    () => [
      columnHelper.accessor('username', {
        header: m.modal_ldap_dry_run_col_username(),
        enableSorting: true,
        sortingFn: 'text',
        size: 160,
        minSize: 160,
        cell: textCell,
      }),
      columnHelper.accessor('change', {
        header: m.modal_ldap_dry_run_col_change(),
        enableSorting: true,
        sortingFn: 'text',
        size: 260,
        minSize: 260,
        cell: textCell,
      }),
      columnHelper.accessor('action', {
        header: m.modal_ldap_dry_run_col_status(),
        enableSorting: true,
        sortingFn: 'text',
        size: 160,
        minSize: 120,
        meta: { flex: true },
        cell: (info) => (
          <TableCell flex>
            <Badge {...statusBadge(info.getValue())} />
          </TableCell>
        ),
      }),
    ],
    [],
  );

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    const filteredData = query
      ? data.filter(
          (row) =>
            row.username.toLowerCase().includes(query) ||
            row.change.toLowerCase().includes(query),
        )
      : data;
    // Removals first: they are the changes to double-check.
    const order: Record<DryRunAction, number> = { remove: 0, update: 1, add: 2 };
    return [...filteredData].sort((a, b) => order[a.action] - order[b.action]);
  }, [data, search]);

  const table = useReactTable({
    columns,
    data: filtered,
    enableRowSelection: false,
    columnResizeMode: 'onChange',
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  if (data.length === 0) {
    return (
      <EmptyState
        icon="users"
        title={m.modal_ldap_dry_run_empty_title()}
        subtitle={m.modal_ldap_dry_run_empty_subtitle()}
      />
    );
  }

  return (
    <>
      <SizedBox height={ThemeSpacing.Xl} />
      <Search
        placeholder={m.modal_ldap_dry_run_search_placeholder()}
        onChange={setSearch}
      />
      <SizedBox height={ThemeSpacing.Xl} />
      {filtered.length === 0 ? (
        <EmptyState
          icon="search"
          title={m.search_empty_common_title()}
          subtitle={m.modal_ldap_dry_run_search_empty_subtitle()}
        />
      ) : (
        <TableBody table={table} maxVisibleRows={10} />
      )}
    </>
  );
};
