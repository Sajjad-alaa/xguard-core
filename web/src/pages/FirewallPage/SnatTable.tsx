import {
  createColumnHelper,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import type { SnatBinding } from '../../shared/api/types';
import { openModal } from '../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../shared/hooks/modalControls/modalTypes';
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
import type { FirewallNames } from './useFirewallNames';

const columnHelper = createColumnHelper<SnatBinding>();

type Props = {
  bindings: SnatBinding[];
  names: FirewallNames;
};

export const SnatTable = ({ bindings, names }: Props) => {
  const label = useMemo(() => {
    const users = new Map(names.users.map((u) => [u.id, u.label]));
    const locations = new Map(names.locations.map((l) => [l.id, l.label]));
    return {
      user: (id: number) => users.get(id) ?? `#${id}`,
      location: (id: number) => locations.get(id) ?? `#${id}`,
    };
  }, [names]);

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.firewall_snat_add(),
      iconLeft: 'plus',
      testId: 'add-snat-binding',
      onClick: () => openModal(ModalName.CESnatBinding, {}),
    }),
    [],
  );

  const columns = useMemo(
    () => [
      columnHelper.accessor('user_id', {
        header: m.firewall_snat_col_user(),
        minSize: 220,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{label.user(info.getValue())}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('location_id', {
        header: m.firewall_snat_col_location(),
        minSize: 180,
        cell: (info) => (
          <TableCell>
            <span>{label.location(info.getValue())}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('public_ip', {
        header: m.firewall_snat_col_ip(),
        minSize: 180,
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        cell: (info) => {
          const binding = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  testId: 'edit',
                  onClick: () => openModal(ModalName.CESnatBinding, { binding }),
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
                      title: m.firewall_snat_delete_title(),
                      contentMd: m.firewall_snat_delete_body(),
                      actionPromise: () => api.firewall.deleteSnatBinding(binding.id),
                      invalidateKeys: [['firewall']],
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () => Snackbar.default(m.firewall_snat_deleted()),
                      onError: () => Snackbar.error(m.firewall_snat_delete_failed()),
                    }),
                },
              ],
            },
          ];
          return <TableEditCell menuItems={menuItems} />;
        },
      }),
    ],
    [label],
  );

  const table = useReactTable({
    columns,
    data: bindings,
    getCoreRowModel: getCoreRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
  });

  if (bindings.length === 0) {
    return (
      <EmptyStateFlexible
        icon="gateway"
        title={m.firewall_snat_empty_title()}
        subtitle={m.firewall_snat_empty_subtitle()}
        primaryAction={addButtonProps}
      />
    );
  }

  return (
    <>
      <TableTop text={m.firewall_snat_title()}>
        <Button {...addButtonProps} />
      </TableTop>
      <TableBody table={table} />
    </>
  );
};
