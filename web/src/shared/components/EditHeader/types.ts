import type { BadgeProps } from '../../xguard-ui/components/Badge/types';
import type { IconKindValue } from '../../xguard-ui/components/Icon';

export interface EditHeaderProps {
  title: string;
  icon?: IconKindValue;
  badgeProps?: BadgeProps;
  subtitle?: string;
}
