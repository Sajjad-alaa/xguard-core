import type { PropsWithChildren } from 'react';
import {
  Icon,
  type IconKindValue,
} from '../../../../../../shared/xguard-ui/components/Icon';
import { isPresent } from '../../../../../../shared/xguard-ui/utils/isPresent';

interface Props extends PropsWithChildren {
  icon?: IconKindValue;
  label?: string;
}

export const PlaygroundPolicyInfoListTestItem = ({ icon, label, children }: Props) => {
  return (
    <div className="item">
      {isPresent(icon) && <Icon size={16} icon={icon} />}
      {isPresent(label) && <p>{label}</p>}
      <div className="content">{children}</div>
    </div>
  );
};
