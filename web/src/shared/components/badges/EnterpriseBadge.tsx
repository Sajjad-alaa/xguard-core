import { m } from '../../../paraglide/messages';
import { Badge } from '../../xguard-ui/components/Badge/Badge';
import type { BadgeProps } from '../../xguard-ui/components/Badge/types';
import { IconKind } from '../../xguard-ui/components/Icon';

export const enterpriseBadgeProps: BadgeProps = {
  variant: 'warning',
  get text() {
    return m.license_plan_enterprise();
  },
  showIcon: true,
  icon: IconKind.StatusPremium,
  iconSize: 16,
};

export const EnterpriseBadge = () => {
  return <Badge {...enterpriseBadgeProps} />;
};
