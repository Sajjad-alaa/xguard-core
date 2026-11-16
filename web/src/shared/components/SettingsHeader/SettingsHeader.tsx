import { Badge } from '../../xguard-ui/components/Badge/Badge';
import type { BadgeProps } from '../../xguard-ui/components/Badge/types';
import { Icon } from '../../xguard-ui/components/Icon';
import type { IconKindValue } from '../../xguard-ui/components/Icon/icon-types';
import { ThemeVariable } from '../../xguard-ui/types';
import { isPresent } from '../../xguard-ui/utils/isPresent';
import './style.scss';

interface SettingsHeaderProps {
  icon: IconKindValue;
  badgeProps?: BadgeProps;
  title: string;
  subtitle: string;
}

export const SettingsHeader = ({
  icon,
  badgeProps,
  title,
  subtitle,
}: SettingsHeaderProps) => {
  return (
    <div className="settings-header">
      <div className="inner-track">
        <div className="icon-track">
          <div className="icon-wrap">
            <div className="bg"></div>
            <Icon icon={icon} size={20} staticColor={ThemeVariable.FgAction} />
          </div>
        </div>
        <div className="content-track">
          <div className="top">
            <h4>{title}</h4>
            {isPresent(badgeProps) && <Badge {...badgeProps} />}
          </div>
          <p>{subtitle}</p>
        </div>
      </div>
    </div>
  );
};
