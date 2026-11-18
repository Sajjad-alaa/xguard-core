// XGuard has no license keys or tiers: every feature implemented in XGuard is
// available. These helpers keep the call sites that used to check a license and
// only report features XGuard does not implement (they were part of the Defguard
// enterprise edition, which is not included) as unavailable.
import {
  LicenseFeature,
  type LicenseFeatureValue,
  type LicenseInfo,
  type LicenseTierValue,
} from '../api/types';

export interface LicenseCheckResult {
  result: boolean;
  error: 'expired' | 'tier' | null;
  tierCheck: 'Business' | 'Enterprise';
}

const UNSUPPORTED_FEATURES: readonly LicenseFeatureValue[] = [
  LicenseFeature.ServiceLocations,
  LicenseFeature.AclAllowedIps,
];

export const isFeatureSupported = (feature?: LicenseFeatureValue | null): boolean =>
  !feature || !UNSUPPORTED_FEATURES.includes(feature);

export const canUseBusinessFeature = (
  _license?: LicenseInfo | null,
): LicenseCheckResult => ({
  result: true,
  error: null,
  tierCheck: 'Business',
});

export const canUseEnterpriseFeature = (
  _license?: LicenseInfo | null,
  feature?: LicenseFeatureValue,
): LicenseCheckResult => {
  const supported = isFeatureSupported(feature);
  return { result: supported, error: supported ? null : 'tier', tierCheck: 'Enterprise' };
};

export const canUseServiceLocations = (_license?: LicenseInfo | null): boolean =>
  isFeatureSupported(LicenseFeature.ServiceLocations);

/** Runs `successCallback` when the feature is available; otherwise does nothing. */
export const licenseActionCheck = (
  checkResult: LicenseCheckResult,
  successCallback: () => void,
): void => {
  if (checkResult.result) {
    successCallback();
  }
};

export const isNavItemLocked = (
  _license: LicenseInfo | null,
  _licenseTier: LicenseTierValue | null | undefined,
  licenseFeature?: LicenseFeatureValue | null,
): boolean => !isFeatureSupported(licenseFeature);

/** Tier checks always pass: XGuard has no license tiers. */
export const tierLicenseCheck = (
  _license: LicenseInfo | null | undefined,
  _licenseTier: LicenseTierValue | null | undefined,
): LicenseCheckResult => ({ result: true, error: null, tierCheck: 'Business' });
