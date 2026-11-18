import { describe, expect, it, vi } from 'vitest';
import { LicenseFeature, LicenseTier } from '../src/shared/api/types';
import {
  canUseBusinessFeature,
  canUseEnterpriseFeature,
  canUseServiceLocations,
  isFeatureSupported,
  isNavItemLocked,
  licenseActionCheck,
  tierLicenseCheck,
} from '../src/shared/utils/license';

describe('XGuard feature availability (no license tiers)', () => {
  it('allows every former Business feature without a license', () => {
    expect(canUseBusinessFeature(null).result).toBe(true);
    expect(canUseBusinessFeature(undefined).error).toBeNull();
    expect(tierLicenseCheck(null, LicenseTier.Enterprise).result).toBe(true);
  });

  it('allows tier-wide and implemented Enterprise features', () => {
    expect(canUseEnterpriseFeature(null).result).toBe(true);
    expect(canUseEnterpriseFeature(null, LicenseFeature.ComponentHa).result).toBe(true);
    expect(canUseEnterpriseFeature(null, LicenseFeature.MfaFlow).result).toBe(true);
    expect(canUseEnterpriseFeature(null, LicenseFeature.Fido2).result).toBe(true);
    expect(canUseEnterpriseFeature(null, LicenseFeature.GroupMTUOverride).result).toBe(
      true,
    );
    // Service locations are implemented in XGuard (daemon-managed tunnels).
    expect(isFeatureSupported(LicenseFeature.ServiceLocations)).toBe(true);
    expect(canUseServiceLocations(null)).toBe(true);
  });

  it('reports features XGuard does not implement as unavailable', () => {
    for (const feature of [LicenseFeature.AclAllowedIps]) {
      expect(isFeatureSupported(feature)).toBe(false);
      expect(canUseEnterpriseFeature(null, feature).result).toBe(false);
      expect(isNavItemLocked(null, LicenseTier.Enterprise, feature)).toBe(true);
    }
  });

  it('runs the action only for available features', () => {
    const action = vi.fn();
    licenseActionCheck(canUseBusinessFeature(null), action);
    expect(action).toHaveBeenCalledTimes(1);
    // FIDO2 VPN MFA and device posture are implemented in XGuard.
    licenseActionCheck(canUseEnterpriseFeature(null, LicenseFeature.Fido2), action);
    expect(action).toHaveBeenCalledTimes(2);
    licenseActionCheck(
      canUseEnterpriseFeature(null, LicenseFeature.DevicePosture),
      action,
    );
    expect(action).toHaveBeenCalledTimes(3);
    // Features XGuard does not implement do not run the action.
    licenseActionCheck(
      canUseEnterpriseFeature(null, LicenseFeature.AclAllowedIps),
      action,
    );
    expect(action).toHaveBeenCalledTimes(3);
  });

  it('does not lock navigation items without a feature', () => {
    expect(isNavItemLocked(null, LicenseTier.Business)).toBe(false);
  });
});
