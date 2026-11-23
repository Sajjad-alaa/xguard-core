import {
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useMemo } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import type { ActivityLogStream } from '../../../shared/api/types';
import { openModal } from '../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../shared/hooks/modalControls/modalTypes';
import { displayDate } from '../../../shared/utils/displayDate';
import { Badge } from '../../../shared/xguard-ui/components/Badge/Badge';
import type { MenuItemsGroup } from '../../../shared/xguard-ui/components/Menu/types';
import { tableEditColumnSize } from '../../../shared/xguard-ui/components/table/consts';
import { TableBody } from '../../../shared/xguard-ui/components/table/TableBody/TableBody';
import { TableCell } from '../../../shared/xguard-ui/components/table/TableCell/TableCell';
import { TableEditCell } from '../../../shared/xguard-ui/components/table/TableEditCell/TableEditCell';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';

type RowData = ActivityLogStream;

const columnHelper = createColumnHelper<RowData>();

type Props = {
  data: RowData[];
};

export const ActivityLogStreamTable = ({ data: rowData }: Props) => {
  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: m.settings_activity_log_streaming_table_header_name(),
        enableSorting: true,
        sortingFn: 'text',
        size: 300,
        minSize: 200,
        meta: {
          flex: true,
        },
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.accessor('stream_type', {
        header: m.settings_activity_log_streaming_table_stream_type_name(),
        size: 200,
        minSize: 100,
        cell: (info) => {
          const type = info.getValue();
          const label =
            type === 'vector_http'
              ? m.modal_vector_destination_title()
              : type === 'logstash_http'
                ? m.modal_logstash_destination_title()
                : type === 'syslog'
                  ? m.modal_syslog_destination_title()
                  : type === 'http'
                    ? m.modal_http_destination_title()
                    : m.modal_splunk_destination_title();
          return (
            <TableCell>
              <span>{label}</span>
            </TableCell>
          );
        },
      }),
      columnHelper.accessor('url', {
        header: m.settings_activity_log_streaming_table_header_url(),
        minSize: 220,
        meta: { flex: true },
        cell: (info) => (
          <TableCell>
            <span>{info.getValue()}</span>
          </TableCell>
        ),
      }),
      columnHelper.display({
        id: 'status',
        header: m.settings_activity_log_streaming_table_header_status(),
        size: 260,
        cell: (info) => {
          const { status } = info.row.original;
          const failing =
            status.last_error_at !== null &&
            (status.last_delivery === null ||
              status.last_error_at > status.last_delivery);
          return (
            <TableCell>
              {failing ? (
                <Badge
                  variant="critical"
                  text={m.settings_activity_log_streaming_status_failing()}
                  title={status.last_error ?? undefined}
                />
              ) : status.last_delivery !== null ? (
                <span>
                  {m.settings_activity_log_streaming_status_delivered({
                    date: displayDate(status.last_delivery),
                  })}
                </span>
              ) : (
                <span>{m.settings_activity_log_streaming_status_waiting()}</span>
              )}
              {status.dropped > 0 && (
                <Badge
                  variant="warning"
                  text={m.settings_activity_log_streaming_status_dropped({
                    count: status.dropped,
                  })}
                />
              )}
            </TableCell>
          );
        },
      }),
      columnHelper.display({
        id: 'edit',
        enableResizing: false,
        header: '',
        enableSorting: false,
        size: tableEditColumnSize,
        cell: (info) => {
          const row = info.row.original;
          const menuItems: MenuItemsGroup[] = [
            {
              items: [
                {
                  text: m.controls_edit(),
                  icon: 'edit',
                  onClick: () => {
                    openModal(ModalName.EditLogStreaming, row);
                  },
                },
                {
                  text: m.settings_activity_log_streaming_send_test(),
                  icon: 'check-circle',
                  onClick: () => {
                    api.activityLogStream
                      .testStream(row)
                      .then(() =>
                        Snackbar.default(
                          m.settings_activity_log_streaming_test_success(),
                        ),
                      )
                      .catch((error) =>
                        Snackbar.error(
                          error?.response?.data?.msg ??
                            m.settings_activity_log_streaming_test_failed(),
                        ),
                      );
                  },
                },
                {
                  text: m.controls_delete(),
                  icon: 'delete',
                  variant: 'danger',
                  onClick: () => {
                    openModal(ModalName.ConfirmAction, {
                      title:
                        m.settings_activity_log_streaming_delete_log_streaming_title(),
                      contentMd: m.modal_delete_logstream_destination(),
                      actionPromise: () => api.activityLogStream.deleteStream(row.id),
                      invalidateKeys: [['activity_log_stream'], ['activity-log']],
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () =>
                        Snackbar.default(
                          m.settings_activity_log_streaming_delete_log_streaming_success(),
                        ),
                      onError: () =>
                        Snackbar.error(
                          m.settings_activity_log_streaming_delete_log_streaming_failed(),
                        ),
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
    [],
  );

  const table = useReactTable({
    columns,
    data: rowData,
    enableRowSelection: false,
    columnResizeMode: 'onChange',
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return <TableBody table={table} />;
};
