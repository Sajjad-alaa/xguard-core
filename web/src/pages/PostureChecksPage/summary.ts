import { m } from '../../paraglide/messages';
import type { ApiDevicePosture, DevicePostureOsType } from '../../shared/api/types';

const OS_NAMES: Record<DevicePostureOsType, string> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
  ios: 'iOS',
  android: 'Android',
};

export const osName = (os: DevicePostureOsType) => OS_NAMES[os];

/** The operating systems a policy allows; none means any system. */
export const systemsSummary = (posture: ApiDevicePosture) =>
  posture.os_rules.length === 0
    ? m.posture_checks_any_system()
    : posture.os_rules.map((rule) => osName(rule.os_type)).join(', ');

export const clientSummary = (posture: ApiDevicePosture) =>
  [posture.min_desktop_client_version, posture.min_mobile_client_version]
    .filter((version): version is string => version !== null)
    .join(' / ') || m.posture_checks_version_any();

export const locationsSummary = (
  posture: ApiDevicePosture,
  names: Map<number, string>,
) =>
  posture.locations.length === 0
    ? m.posture_checks_no_locations()
    : posture.locations.map((id) => names.get(id) ?? `#${id}`).join(', ');
