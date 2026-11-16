import './style.scss';
import type { MouseEventHandler, PropsWithChildren } from 'react';
import { Badge } from '../../shared/xguard-ui/components/Badge/Badge';
import type { BadgeProps } from '../../shared/xguard-ui/components/Badge/types';
import { Fold } from '../../shared/xguard-ui/components/Fold/Fold';
import { RadioIndicator } from '../../shared/xguard-ui/components/RadioIndicator/RadioIndicator';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { isPresent } from '../../shared/xguard-ui/utils/isPresent';

type Props = {
  title: string;
  subtitle: string;
  active: boolean;
  onClick: MouseEventHandler<HTMLDivElement>;
  badge?: BadgeProps;
} & PropsWithChildren;

export const FoldableRadioSection = ({
  active,
  subtitle,
  title,
  onClick,
  badge,
  children,
}: Props) => {
  return (
    <div className="foldable-radio-section">
      <div className="top" onClick={onClick}>
        <RadioIndicator active={active} />
        <div className="content">
          <div className="header">
            <p className="title">{title}</p>
            {isPresent(badge) && <Badge {...badge} />}
          </div>
          <p className="subtitle">{subtitle}</p>
        </div>
      </div>
      <div className="bottom">
        <Fold open={active}>
          <SizedBox height={ThemeSpacing.Xl2} />
          {children}
        </Fold>
      </div>
    </div>
  );
};
