import { useMutation } from '@tanstack/react-query';
import {
  createColumnHelper,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import type { ApiDevicePosture } from '../../shared/api/types';
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
import { clientSummary, locationsSummary, systemsSummary } from './summary';

const columnHelper = createColumnHelper<ApiDevicePosture>();
const invalidate = [['device-posture'], ['network']];

type Props = {
  postures: ApiDevicePosture[];
  locationNames: Map<number, string>;
};

export const PostureChecksTable = ({ postures, locationNames }: Props) => {
  const { mutate: duplicate } = useMutation({
    mutationFn: api.devicePosture.duplicateDevicePosture,
    meta: { invalidate },
    onSuccess: () => Snackbar.default(m.posture_checks_duplicate_success()),
    onError: () => Snackbar.error(m.posture_checks_duplicate_failed()),
  });

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.posture_checks_button_add(),
      iconLeft: 'add-rule',
      testId: 'add-posture-check',
      onClick: () => openModal(ModalName.CEPostureCheck, {}),
    }),
    [],
  );

  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: m.posture_checks_col_name(),
        minSize: 180,
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'systems',
        header: m.posture_checks_col_systems(),
        minSize: 200,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{systemsSummary(info.row.original)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'client',
        header: m.posture_checks_col_client(),
        minSize: 140,
        cell: (info) => (
          <TableCell>
            <span>{clientSummary(info.row.original)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'locations',
        header: m.posture_checks_col_locations(),
        minSize: 200,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{locationsSummary(info.row.original, locationNames)}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        cell: (info) => {
          const posture = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  testId: 'edit',
                  onClick: () => openModal(ModalName.CEPostureCheck, { posture }),
                },
                {
                  text: m.posture_checks_menu_duplicate(),
                  icon: 'copy',
                  testId: 'duplicate',
                  onClick: () => duplicate(posture.id),
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
                      title: m.posture_checks_delete_confirm_title(),
                      contentMd: m.posture_checks_delete_confirm_body({
                        name: posture.name,
                      }),
                      actionPromise: () =>
                        api.devicePosture.deleteDevicePosture(posture.id),
                      invalidateKeys: invalidate,
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () =>
                        Snackbar.default(m.posture_checks_delete_success()),
                      onError: () => Snackbar.error(m.posture_checks_delete_failed()),
                    }),
                },
              ],
            },
          ];
          return <TableEditCell menuItems={menuItems} />;
        },
      }),
    ],
    [duplicate, locationNames],
  );

  const table = useReactTable({
    columns,
    data: postures,
    getCoreRowModel: getCoreRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
  });

  if (postures.length === 0) {
    return (
      <EmptyStateFlexible
        icon="posture-checks"
        title={m.posture_checks_empty_title()}
        subtitle={m.posture_checks_empty_subtitle()}
        primaryAction={addButtonProps}
      />
    );
  }

  return (
    <>
      <TableTop text={m.posture_checks_table_title()}>
        <Button {...addButtonProps} />
      </TableTop>
      <TableBody table={table} />
    </>
  );
};
