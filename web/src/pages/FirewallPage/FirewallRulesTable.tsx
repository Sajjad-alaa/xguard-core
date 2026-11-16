import { useMutation } from '@tanstack/react-query';
import {
  createColumnHelper,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import type { FirewallRule } from '../../shared/api/types';
import { openModal } from '../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../shared/hooks/modalControls/modalTypes';
import { Badge } from '../../shared/xguard-ui/components/Badge/Badge';
import { Button } from '../../shared/xguard-ui/components/Button/Button';
import type { ButtonProps } from '../../shared/xguard-ui/components/Button/types';
import { EmptyStateFlexible } from '../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import type { MenuItemsGroup } from '../../shared/xguard-ui/components/Menu/types';
import { tableEditColumnSize } from '../../shared/xguard-ui/components/table/consts';
import { TableBody } from '../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../shared/xguard-ui/components/table/TableCell/TableCell';
import { TableEditCell } from '../../shared/xguard-ui/components/table/TableEditCell/TableEditCell';
import { TableTop } from '../../shared/xguard-ui/components/table/TableTop/TableTop';
import { Snackbar } from '../../shared/xguard-ui/providers/snackbar/snackbar';
import { ruleToInput } from './modals/CEFirewallRuleModal/form';
import {
  actionLabel,
  destinationsSummary,
  isExpired,
  locationsSummary,
  servicesSummary,
  sourcesSummary,
} from './summary';
import type { FirewallNames } from './useFirewallNames';

const columnHelper = createColumnHelper<FirewallRule>();

const invalidate = [['firewall']];

type Props = {
  rules: FirewallRule[];
  names: FirewallNames;
};

export const FirewallRulesTable = ({ rules, names }: Props) => {
  const { mutate: toggleRule } = useMutation({
    mutationFn: api.firewall.editRule,
    meta: { invalidate },
    onError: () => Snackbar.error(m.firewall_save_failed()),
  });

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.firewall_add(),
      iconLeft: 'add-rule',
      testId: 'add-firewall-rule',
      onClick: () => openModal(ModalName.CEFirewallRule, {}),
    }),
    [],
  );

  const columns = useMemo(
    () => [
      columnHelper.accessor('priority', {
        header: m.firewall_col_order(),
        size: 90,
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('name', {
        header: m.firewall_col_name(),
        minSize: 180,
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('action', {
        header: m.firewall_col_action(),
        size: 120,
        cell: (info) => {
          const rule = info.row.original;
          if (!rule.enabled) {
            return (
              <TableCell>
                <Badge variant="neutral" text={m.state_disabled()} />
              </TableCell>
            );
          }
          if (isExpired(rule)) {
            return (
              <TableCell>
                <Badge variant="neutral" text={m.firewall_expired()} />
              </TableCell>
            );
          }
          return (
            <TableCell>
              <Badge
                variant={info.getValue() === 'allow' ? 'success' : 'critical'}
                text={actionLabel(info.getValue())}
              />
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'sources',
        header: m.firewall_col_sources(),
        minSize: 200,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{sourcesSummary(info.row.original, names)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'destinations',
        header: m.firewall_col_destinations(),
        minSize: 200,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{destinationsSummary(info.row.original)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'services',
        header: m.firewall_col_services(),
        minSize: 150,
        cell: (info) => (
          <TableCell>
            <span>{servicesSummary(info.row.original)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'locations',
        header: m.firewall_col_locations(),
        minSize: 150,
        cell: (info) => (
          <TableCell>
            <span>{locationsSummary(info.row.original, names)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        cell: (info) => {
          const rule = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  testId: 'edit',
                  onClick: () => openModal(ModalName.CEFirewallRule, { rule }),
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
    [names, toggleRule],
  );

  const table = useReactTable({
    columns,
    data: rules,
    getCoreRowModel: getCoreRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
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

  return (
    <>
      <TableTop text={m.firewall_table_title()}>
        <Button {...addButtonProps} />
      </TableTop>
      <TableBody table={table} />
    </>
  );
};
