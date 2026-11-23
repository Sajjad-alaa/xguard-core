import { useMutation } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import {
  type ColumnFiltersState,
  createColumnHelper,
  type FilterFn,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo, useState } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import { type FirewallRule, FirewallRuleAction } from '../../shared/api/types';
import type { SelectionOption } from '../../shared/components/SelectionSection/type';
import { TableBadgesCell } from '../../shared/components/TableBadgesCell/TableBadgesCell';
import { openModal } from '../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../shared/hooks/modalControls/modalTypes';
import { displayDate } from '../../shared/utils/displayDate';
import { Badge } from '../../shared/xguard-ui/components/Badge/Badge';
import { Button } from '../../shared/xguard-ui/components/Button/Button';
import type { ButtonProps } from '../../shared/xguard-ui/components/Button/types';
import { EmptyStateFlexible } from '../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import type { MenuItemsGroup } from '../../shared/xguard-ui/components/Menu/types';
import { Search } from '../../shared/xguard-ui/components/Search/Search';
import { tableEditColumnSize } from '../../shared/xguard-ui/components/table/consts';
import { TableBody } from '../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../shared/xguard-ui/components/table/TableCell/TableCell';
import { TableEditCell } from '../../shared/xguard-ui/components/table/TableEditCell/TableEditCell';
import { TableTop } from '../../shared/xguard-ui/components/table/TableTop/TableTop';
import type { TableFilterMessages } from '../../shared/xguard-ui/components/table/types';
import { Snackbar } from '../../shared/xguard-ui/providers/snackbar/snackbar';
import { ruleToInput } from './rule/form';
import {
  actionIcon,
  actionLabel,
  actionVariant,
  destinationItems,
  locationItems,
  RuleStatus,
  type RuleStatusValue,
  ruleSearchText,
  ruleStatus,
  serviceItems,
  sourceItems,
} from './summary';
import type { FirewallNames } from './useFirewallNames';
import type { LocationPolicies } from './useLocationPolicies';

const columnHelper = createColumnHelper<FirewallRule>();

const invalidate = [['firewall']];

/** Keeps rows whose value is one of the selected filter options. */
const inSelection: FilterFn<FirewallRule> = (row, columnId, selected: unknown) =>
  !Array.isArray(selected) || selected.length === 0
    ? true
    : selected.includes(row.getValue(columnId));

export const statusLabel = (status: RuleStatusValue) => {
  switch (status) {
    case RuleStatus.Active:
      return m.state_active();
    case RuleStatus.Disabled:
      return m.state_disabled();
    case RuleStatus.Expired:
      return m.firewall_expired();
  }
};

const StatusBadge = ({ rule }: { rule: FirewallRule }) => {
  const status = ruleStatus(rule);
  switch (status) {
    case RuleStatus.Active:
      return (
        <Badge
          variant="success"
          showIcon
          text={statusLabel(status)}
          title={
            rule.expires_at
              ? m.firewall_status_until({ date: displayDate(rule.expires_at) })
              : undefined
          }
        />
      );
    case RuleStatus.Disabled:
      return <Badge variant="neutral" showIcon text={statusLabel(status)} />;
    case RuleStatus.Expired:
      return (
        <Badge
          variant="warning"
          showIcon
          icon="pending"
          text={statusLabel(status)}
          title={m.firewall_status_expired_at({
            date: displayDate(rule.expires_at ?? ''),
          })}
        />
      );
  }
};

type Props = {
  rules: FirewallRule[];
  names: FirewallNames;
  policies: LocationPolicies;
};

export const FirewallRulesTable = ({ rules, names, policies }: Props) => {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

  const { mutate: toggleRule } = useMutation({
    mutationFn: api.firewall.editRule,
    meta: { invalidate },
    onSuccess: (_, rule) =>
      Snackbar.default(
        rule.enabled ? m.firewall_enabled_success() : m.firewall_disabled_success(),
      ),
    onError: () => Snackbar.error(m.firewall_save_failed()),
  });

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.firewall_add(),
      iconLeft: 'add-rule',
      testId: 'add-firewall-rule',
      onClick: () => navigate({ to: '/firewall/add-rule' }),
    }),
    [navigate],
  );

  const filterMessages: TableFilterMessages = useMemo(
    () => ({
      searchPlaceholder: m.controls_search(),
      clearButton: m.controls_reset(),
      applyButton: m.controls_submit(),
      emptyState: m.search_empty_common_title(),
    }),
    [],
  );

  const actionOptions = useMemo(
    (): SelectionOption<string>[] =>
      Object.values(FirewallRuleAction).map((action) => ({
        id: action,
        label: actionLabel(action),
      })),
    [],
  );

  const statusOptions = useMemo(
    (): SelectionOption<string>[] =>
      Object.values(RuleStatus).map((status) => ({
        id: status,
        label: statusLabel(status),
      })),
    [],
  );

  const visibleRules = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return rules;
    return rules.filter((rule) => ruleSearchText(rule, names).includes(query));
  }, [rules, names, search]);

  const columns = useMemo(
    () => [
      columnHelper.accessor('priority', {
        header: m.firewall_col_order(),
        size: 90,
        minSize: 80,
        enableSorting: true,
        cell: (info) => (
          <TableCell>
            <span className="rule-order">{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('name', {
        header: m.firewall_col_name(),
        minSize: 220,
        enableSorting: true,
        sortingFn: 'text',
        meta: { flex: true },
        cell: (info) => {
          const rule = info.row.original;
          return (
            <TableCell className="rule-name-cell">
              <div className="rule-name" title={rule.description || rule.name}>
                <span className="name">{rule.name}</span>
                {rule.description && (
                  <span className="description">{rule.description}</span>
                )}
              </div>
            </TableCell>
          );
        },
      }),
      columnHelper.accessor((rule) => ruleStatus(rule), {
        id: 'status',
        header: m.col_status(),
        size: 130,
        minSize: 120,
        enableSorting: true,
        enableColumnFilter: true,
        filterFn: inSelection,
        meta: { filterOptions: statusOptions },
        cell: (info) => (
          <TableCell>
            <StatusBadge rule={info.row.original} />
          </TableCell>
        ),
      }),
      columnHelper.accessor('action', {
        header: m.firewall_col_action(),
        size: 120,
        minSize: 110,
        enableSorting: true,
        enableColumnFilter: true,
        filterFn: inSelection,
        meta: { filterOptions: actionOptions },
        cell: (info) => (
          <TableCell>
            <Badge
              variant={actionVariant(info.getValue())}
              showIcon
              icon={actionIcon(info.getValue())}
              text={actionLabel(info.getValue())}
            />
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'sources',
        header: m.firewall_col_sources(),
        size: 260,
        minSize: 200,
        cell: (info) => <TableBadgesCell items={sourceItems(info.row.original, names)} />,
      }),
      columnHelper.display({
        id: 'destinations',
        header: m.firewall_col_destinations(),
        size: 240,
        minSize: 180,
        cell: (info) => <TableBadgesCell items={destinationItems(info.row.original)} />,
      }),
      columnHelper.display({
        id: 'services',
        header: m.firewall_col_services(),
        size: 190,
        minSize: 150,
        cell: (info) => (
          <TableBadgesCell items={serviceItems(info.row.original)} limit={3} />
        ),
      }),
      columnHelper.display({
        id: 'locations',
        header: m.firewall_col_locations(),
        size: 200,
        minSize: 160,
        cell: (info) => (
          <TableBadgesCell items={locationItems(info.row.original, names)} />
        ),
      }),
      columnHelper.display({
        id: 'enforced',
        header: m.firewall_col_enforced(),
        size: 170,
        minSize: 140,
        cell: (info) => {
          const rule = info.row.original;
          if (policies.loading) {
            return (
              <TableCell>
                <Skeleton width={90} height={20} />
              </TableCell>
            );
          }
          if (ruleStatus(rule) !== RuleStatus.Active || policies.error) {
            return (
              <TableCell>
                <span className="muted">{m.firewall_enforced_not_applicable()}</span>
              </TableCell>
            );
          }
          const count = policies.ruleLocations.get(rule.id)?.length ?? 0;
          return (
            <TableCell>
              {count > 0 ? (
                <Badge
                  variant="success"
                  showIcon
                  icon="check-filled"
                  text={m.firewall_enforced_count({ count })}
                />
              ) : (
                <Badge
                  variant="warning"
                  showIcon
                  icon="warning-filled"
                  text={m.firewall_enforced_none()}
                  title={m.firewall_enforced_none_help()}
                />
              )}
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        enableResizing: false,
        cell: (info) => {
          const rule = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  testId: 'edit',
                  onClick: () =>
                    navigate({
                      to: '/firewall/$ruleId/edit',
                      params: { ruleId: String(rule.id) },
                    }),
                },
                {
                  text: m.controls_duplicate(),
                  icon: 'duplicate',
                  testId: 'duplicate',
                  onClick: () =>
                    navigate({
                      to: '/firewall/add-rule',
                      search: { duplicate: rule.id },
                    }),
                },
                {
                  text: rule.enabled ? m.controls_disable() : m.controls_enable(),
                  icon: rule.enabled ? 'disabled' : 'check-circle',
                  testId: 'change-state',
                  onClick: () =>
                    toggleRule({
                      id: rule.id,
                      ...ruleToInput(rule),
                      enabled: !rule.enabled,
                    }),
                },
              ],
            },
            {
              items: [
                {
                  text: m.controls_delete(),
                  icon: 'delete',
                  testId: 'delete',
                  variant: 'danger',
                  onClick: () =>
                    openModal(ModalName.ConfirmAction, {
                      title: m.firewall_delete_confirm_title(),
                      contentMd: m.firewall_delete_confirm_body({ name: rule.name }),
                      actionPromise: () => api.firewall.deleteRule(rule.id),
                      invalidateKeys: invalidate,
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () => Snackbar.default(m.firewall_delete_success()),
                      onError: () => Snackbar.error(m.firewall_delete_failed()),
                    }),
                },
              ],
            },
          ];
          return <TableEditCell menuItems={menuItems} />;
        },
      }),
    ],
    [names, policies, toggleRule, navigate, actionOptions, statusOptions],
  );

  const table = useReactTable({
    initialState: {
      sorting: [{ id: 'priority', desc: false }],
    },
    state: { columnFilters },
    meta: { filterMessages },
    columns,
    data: visibleRules,
    getRowId: (rule) => String(rule.id),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  if (rules.length === 0) {
    return (
      <EmptyStateFlexible
        icon="rules"
        title={m.firewall_empty_title()}
        subtitle={m.firewall_empty_subtitle()}
        primaryAction={addButtonProps}
      />
    );
  }

  const noMatches = table.getRowModel().rows.length === 0;

  return (
    <>
      <TableTop text={m.firewall_table_title()}>
        <Search placeholder={m.firewall_search()} value={search} onChange={setSearch} />
        <Button {...addButtonProps} />
      </TableTop>
      <TableBody table={table} />
      {noMatches && (
        <EmptyStateFlexible
          icon="search"
          title={m.search_empty_common_title()}
          subtitle={m.search_empty_common_subtitle()}
        />
      )}
    </>
  );
};
