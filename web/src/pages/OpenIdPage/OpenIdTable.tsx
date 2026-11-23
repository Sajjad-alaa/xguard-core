import { useMutation, useSuspenseQuery } from '@tanstack/react-query';
import {
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo, useState } from 'react';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import type { OpenIdClient } from '../../shared/api/types';
import { openModal } from '../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../shared/hooks/modalControls/modalTypes';
import { getOpenIdClientQueryOptions } from '../../shared/query';
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
import { useClipboard } from '../../shared/xguard-ui/hooks/useClipboard';
import { Snackbar } from '../../shared/xguard-ui/providers/snackbar/snackbar';

type RowData = OpenIdClient;

const columnHelper = createColumnHelper<RowData>();

export const OpenIdClientTable = () => {
  const { data } = useSuspenseQuery(getOpenIdClientQueryOptions);
  const [search, setSearch] = useState('');

  const reservedNames = useMemo(
    () => data.map((c) => c.name.toLowerCase().replaceAll(' ', '')),
    [data],
  );

  const visibleClients = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return data;
    return data.filter(
      (c) =>
        c.name.toLowerCase().includes(query) || c.client_id.toLowerCase().includes(query),
    );
  }, [data, search]);

  const { writeToClipboard } = useClipboard();

  const { mutate: toggleClient } = useMutation({
    mutationFn: api.openIdClient.changeOpenIdClientState,
    meta: {
      invalidate: ['oauth'],
    },
  });

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.openid_add_application(),
      iconLeft: 'openid',
      testId: 'add-new-app',
      onClick: () => {
        openModal(ModalName.CEOpenIdClient, {
          reservedNames,
        });
      },
    }),
    [reservedNames],
  );

  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: m.openid_table_header_app_name(),
        enableSorting: true,
        sortingFn: 'text',
        size: 300,
        minSize: 220,
        meta: {
          flex: true,
        },
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('client_id', {
        header: m.openid_table_header_client_id(),
        size: 260,
        minSize: 200,
        cell: (info) => (
          <TableCell>
            <Badge variant="outlined" text={info.getValue()} title={info.getValue()} />
          </TableCell>
        ),
      }),
      columnHelper.accessor('enabled', {
        header: m.col_status(),
        minSize: 130,
        enableSorting: true,
        cell: (info) => (
          <TableCell>
            {info.getValue() ? (
              <Badge
                variant="success"
                showIcon
                icon="check-filled"
                text={m.state_enabled()}
              />
            ) : (
              <Badge
                variant="critical"
                showIcon
                icon="disabled"
                text={m.state_disabled()}
              />
            )}
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        enableResizing: false,
        cell: (info) => {
          const row = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  onClick: () => {
                    openModal(ModalName.CEOpenIdClient, {
                      reservedNames,
                      openIdClient: row,
                    });
                  },
                },
                {
                  icon: 'activity-notes',
                  text: m.openid_edit_copy_id(),
                  testId: 'copy-id',
                  onClick: () => {
                    writeToClipboard(row.client_id);
                  },
                },
                {
                  icon: 'copy',
                  text: m.openid_edit_copy_secret(),
                  testId: 'copy-secret',
                  onClick: () => {
                    writeToClipboard(row.client_secret);
                  },
                },
                {
                  icon: row.enabled ? 'disabled' : 'check-circle',
                  text: row.enabled ? m.controls_disable() : m.controls_enable(),
                  onClick: () => {
                    toggleClient({
                      client_id: row.client_id,
                      enabled: !row.enabled,
                    });
                  },
                },
              ],
            },
            {
              items: [
                {
                  text: m.controls_delete(),
                  icon: 'delete',
                  variant: 'danger',
                  onClick: () => {
                    openModal(ModalName.ConfirmAction, {
                      title: m.modal_delete_openid_client_title(),
                      contentMd: m.modal_delete_openid_client_body(),
                      actionPromise: () =>
                        api.openIdClient.deleteOpenIdClient(row.client_id),
                      invalidateKeys: [['oauth']],
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () => Snackbar.default(m.openid_delete_success()),
                      onError: () => Snackbar.error(m.openid_delete_failed()),
                    });
                  },
                },
              ],
            },
          ];
          return <TableEditCell menuItems={menuItems} />;
        },
      }),
    ],
    [reservedNames, writeToClipboard, toggleClient],
  );

  const table = useReactTable({
    columns,
    data: visibleClients,
    getRowId: (row) => row.client_id,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
  });

  if (data.length === 0) {
    return (
      <EmptyStateFlexible
        icon="openid"
        title={m.openid_empty_title()}
        subtitle={m.openid_empty_subtitle()}
        primaryAction={addButtonProps}
      />
    );
  }

  const noMatches = table.getRowModel().rows.length === 0;

  return (
    <>
      <TableTop text={m.openid_table_top_title()}>
        <Search placeholder={m.openid_search()} value={search} onChange={setSearch} />
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
