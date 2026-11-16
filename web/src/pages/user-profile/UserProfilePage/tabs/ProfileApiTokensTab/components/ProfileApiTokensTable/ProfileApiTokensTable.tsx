import {
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import { m } from '../../../../../../../paraglide/messages';
import api from '../../../../../../../shared/api/api';
import type { ApiToken } from '../../../../../../../shared/api/types';
import { openModal } from '../../../../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../../../../shared/hooks/modalControls/modalTypes';
import { tableSortingFns } from '../../../../../../../shared/utils/dateSortingFn';
import { displayDate } from '../../../../../../../shared/utils/displayDate';
import { Badge } from '../../../../../../../shared/xguard-ui/components/Badge/Badge';
import { tableEditColumnSize } from '../../../../../../../shared/xguard-ui/components/table/consts';
import { TableBody } from '../../../../../../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../../../../../../shared/xguard-ui/components/table/TableCell/TableCell';
import { TableEditCell } from '../../../../../../../shared/xguard-ui/components/table/TableEditCell/TableEditCell';
import { Snackbar } from '../../../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { useUserProfile } from '../../../../hooks/useUserProfilePage';
import { isExpired } from '../../apiTokens';

const columnHelper = createColumnHelper<ApiToken>();

export const ProfileApiTokensTable = () => {
  const username = useUserProfile((s) => s.user.username);
  const data = useUserProfile((s) => s.apiTokens);

  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        enableSorting: true,
        sortingFn: 'text',
        header: m.profile_api_tokens_col_name(),
        minSize: 220,
        meta: {
          flex: true,
        },
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
            <code className="api-token-hint">{info.row.original.hint}…</code>
          </TableCell>
        ),
      }),
      columnHelper.accessor('read_only', {
        header: m.profile_api_tokens_col_access(),
        size: 120,
        cell: (info) => (
          <TableCell>
            <Badge
              variant={info.getValue() ? 'neutral' : 'warning'}
              text={
                info.getValue()
                  ? m.profile_api_tokens_access_read_only()
                  : m.profile_api_tokens_access_full()
              }
            />
          </TableCell>
        ),
      }),
      columnHelper.accessor('created_at', {
        header: m.col_created_at(),
        size: 175,
        minSize: 175,
        enableSorting: true,
        // @ts-expect-error
        sortingFn: 'dateIso',
        cell: (info) => (
          <TableCell>
            <span>{displayDate(info.getValue())}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('expires_at', {
        header: m.profile_api_tokens_col_expires(),
        size: 175,
        minSize: 175,
        cell: (info) => {
          const token = info.row.original;
          const expiresAt = info.getValue();
          return (
            <TableCell>
              {isExpired(token) ? (
                <Badge variant="critical" text={m.profile_api_tokens_expired()} />
              ) : (
                <span>
                  {expiresAt === null
                    ? m.profile_api_tokens_never()
                    : displayDate(expiresAt)}
                </span>
              )}
            </TableCell>
          );
        },
      }),
      columnHelper.accessor('last_used_at', {
        header: m.profile_api_tokens_col_last_used(),
        size: 240,
        minSize: 200,
        cell: (info) => {
          const lastUsed = info.getValue();
          const ip = info.row.original.last_used_ip;
          return (
            <TableCell>
              <span>
                {lastUsed === null
                  ? m.profile_api_tokens_never()
                  : m.profile_api_tokens_last_used({
                      date: displayDate(lastUsed),
                      ip: ip ?? '-',
                    })}
              </span>
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'edit',
        header: '',
        size: tableEditColumnSize,
        cell: (info) => {
          const rowData = info.row.original;
          return (
            <TableEditCell
              menuItems={[
                {
                  items: [
                    {
                      icon: 'edit',
                      testId: 'edit',
                      text: m.controls_rename(),
                      onClick: () => {
                        openModal(ModalName.RenameApiToken, {
                          id: rowData.id,
                          name: rowData.name,
                          username,
                        });
                      },
                    },
                    {
                      icon: 'delete',
                      testId: 'delete',
                      variant: 'danger',
                      text: m.profile_api_tokens_menu_revoke(),
                      onClick: () => {
                        openModal(ModalName.ConfirmAction, {
                          title: m.modal_delete_api_token_title(),
                          contentMd: m.modal_delete_api_token_content({
                            name: rowData.name,
                          }),
                          actionPromise: () =>
                            api.user.deleteApiToken({ id: rowData.id, username }),
                          invalidateKeys: [['user', username, 'api_token']],
                          submitProps: {
                            text: m.profile_api_tokens_menu_revoke(),
                            variant: 'critical',
                          },
                          onSuccess: () =>
                            Snackbar.default(m.modal_delete_api_token_success()),
                          onError: () => Snackbar.error(m.modal_delete_api_token_error()),
                        });
                      },
                    },
                  ],
                },
              ]}
            />
          );
        },
      }),
    ],
    [username],
  );

  const table = useReactTable({
    initialState: {
      sorting: [{ id: 'created_at', desc: true }],
    },
    sortingFns: tableSortingFns,
    columns,
    data,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    enableRowSelection: false,
    columnResizeMode: 'onChange',
  });

  return <TableBody table={table} />;
};
