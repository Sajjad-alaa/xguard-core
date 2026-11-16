import type { IconKindValue } from '../../../../xguard-ui/components/Icon';

export type TopBarLicenseProgressProps = {
  icon: IconKindValue;
  label?: string;
  value: number;
  maxValue: number;
};
