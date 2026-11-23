import { useMutation } from '@tanstack/react-query';
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
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import type { ApiDevicePosture, DevicePostureOsType } from '../../shared/api/types';
import type { SelectionOption } from '../../shared/components/SelectionSection/type';
import { TableBadgesCell } from '../../shared/components/TableBadgesCell/TableBadgesCell';
import { openModal } from '../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../shared/hooks/modalControls/modalTypes';
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
import {
  ALL_OS_TYPES,
  clientItems,
  locationItems,
  osName,
  postureSearchText,
  systemItems,
} from './summary';

const columnHelper = createColumnHelper<ApiDevicePosture>();
const invalidate = [['device-posture'], ['network']];

const matchesSelectedOs: FilterFn<ApiDevicePosture> = (
  row,
  _columnId,
  selected: unknown,
) => {
  if (!Array.isArray(selected) || selected.length === 0) return true;
  const rules = row.original.os_rules;
  if (rules.length === 0) return true;
  return rules.some((rule) => selected.includes(rule.os_type));
};

type Props = {
  postures: ApiDevicePosture[];
  locationNames: Map<number, string>;
};

export const PostureChecksTable = ({ postures, locationNames }: Props) => {
  const [search, setSearch] = useState('');
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

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

  const filterMessages: TableFilterMessages = useMemo(
    () => ({
      searchPlaceholder: m.controls_search(),
      clearButton: m.controls_reset(),
      applyButton: m.controls_submit(),
      emptyState: m.search_empty_common_title(),
    }),
    [],
  );

  const osOptions = useMemo(
    (): SelectionOption<DevicePostureOsType>[] =>
      ALL_OS_TYPES.map((os) => ({ id: os, label: osName(os) })),
    [],
  );

  const visiblePostures = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return postures;
    return postures.filter((p) => postureSearchText(p, locationNames).includes(query));
  }, [postures, locationNames, search]);

  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: m.posture_checks_col_name(),
        minSize: 220,
        enableSorting: true,
        sortingFn: 'text',
        meta: { flex: true },
        cell: (info) => {
          const posture = info.row.original;
          return (
            <TableCell className="posture-name-cell">
              <div className="posture-name" title={posture.description || posture.name}>
                <span className="name">{posture.name}</span>
                {posture.description && (
                  <span className="description">{posture.description}</span>
                )}
              </div>
            </TableCell>
          );
        },
      }),
      columnHelper.accessor((p) => p.os_rules.map((r) => r.os_type), {
        id: 'systems',
        header: m.posture_checks_col_systems(),
        size: 260,
        minSize: 200,
        enableColumnFilter: true,
        filterFn: matchesSelectedOs,
        meta: { filterOptions: osOptions },
        cell: (info) => (
          <TableBadgesCell items={systemItems(info.row.original)} limit={3} />
        ),
      }),
      columnHelper.display({
        id: 'client',
        header: m.posture_checks_col_client(),
        size: 240,
        minSize: 180,
        cell: (info) => (
          <TableBadgesCell items={clientItems(info.row.original)} limit={3} />
        ),
      }),
      columnHelper.display({
        id: 'locations',
        header: m.posture_checks_col_locations(),
        size: 220,
        minSize: 180,
        cell: (info) => (
          <TableBadgesCell
            items={locationItems(info.row.original, locationNames)}
            emptyText={m.posture_checks_no_locations()}
          />
        ),
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        enableResizing: false,
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
                  icon: 'duplicate',
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
    [duplicate, locationNames, osOptions],
  );

  const table = useReactTable({
    initialState: { sorting: [{ id: 'name', desc: false }] },
    state: { columnFilters },
    meta: { filterMessages },
    columns,
    data: visiblePostures,
    getRowId: (posture) => String(posture.id),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
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

  const noMatches = table.getRowModel().rows.length === 0;

  return (
    <>
      <TableTop text={m.posture_checks_table_title()}>
        <Search
          placeholder={m.posture_checks_search()}
          value={search}
          onChange={setSearch}
        />
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
