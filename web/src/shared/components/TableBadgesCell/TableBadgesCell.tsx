import './style.scss';
import clsx from 'clsx';
import { m } from '../../../paraglide/messages';
import { openModal } from '../../hooks/modalControls/modalsSubjects';
import { ModalName } from '../../hooks/modalControls/modalTypes';
import { Badge } from '../../xguard-ui/components/Badge/Badge';
import type { BadgeVariantValue } from '../../xguard-ui/components/Badge/types';
import type { IconKindValue } from '../../xguard-ui/components/Icon/icon-types';
import { TableCell } from '../../xguard-ui/components/table/TableCell/TableCell';
import type { TableCellProps } from '../../xguard-ui/components/table/TableCell/types';

export type TableBadgeItem = {
  key: string;
  label: string;
  icon?: IconKindValue;
  variant?: BadgeVariantValue;
};

interface Props extends Omit<TableCellProps, 'children'> {
  items: TableBadgeItem[];
  /** How many badges fit before the rest collapse into a "+N" button. */
  limit?: number;
  /** Shown as muted text when there is nothing to list. */
  emptyText?: string;
}

/**
 * A table cell that lists values as badges. Values past `limit` collapse into a "+N" button
 * that opens the full list, so long selections keep rows at a single line.
 */
export const TableBadgesCell = ({
  items,
  limit = 2,
  emptyText,
  className,
  ...cellProps
}: Props) => {
  const shown = items.slice(0, limit);
  const hidden = items.length - shown.length;

  return (
    <TableCell className={clsx('table-badges-cell', className)} {...cellProps}>
      {items.length === 0 && emptyText !== undefined && (
        <span className="empty">{emptyText}</span>
      )}
      {shown.map((item) => (
        <Badge
          key={item.key}
          text={item.label}
          title={item.label}
          variant={item.variant ?? 'neutral'}
          icon={item.icon}
          showIcon={item.icon !== undefined}
        />
      ))}
      {hidden > 0 && (
        <button
          type="button"
          className="more"
          aria-label={m.cmp_table_badges_show_all({ count: items.length })}
          onClick={(e) => {
            e.stopPropagation();
            openModal(ModalName.DisplayList, {
              data: items.map((item) => item.label),
            });
          }}
        >
          <Badge variant="outlined" text={`+${hidden}`} />
        </button>
      )}
    </TableCell>
  );
};
