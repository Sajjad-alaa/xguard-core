import './style.scss';
import clsx from 'clsx';
import { Icon } from '../../xguard-ui/components/Icon';
import { ThemeVariable } from '../../xguard-ui/types';
import { policyOsVariantToIcon, policyOsVariantToText } from '../../utils/policyPostures';
import type { SystemSelectorProps } from './types';

export const SystemSelector = ({ os: variant, onClick }: SystemSelectorProps) => {
  return (
    <div
      className={clsx('system-selector', `variant-${variant}`)}
      onClick={() => {
        onClick?.();
      }}
    >
      <div className="icon-track">
        <Icon
          className="system-icon"
          icon={policyOsVariantToIcon(variant)}
          size={20}
          staticColor={ThemeVariable.FgAction}
        />
        <Icon
          className="plus-icon"
          icon="plus"
          size={20}
          staticColor={ThemeVariable.FgAction}
        />
      </div>
      <p>{policyOsVariantToText(variant)}</p>
    </div>
  );
};
