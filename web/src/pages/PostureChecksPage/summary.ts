import { m } from '../../paraglide/messages';
import type { ApiDevicePosture, DevicePostureOsType } from '../../shared/api/types';
import type { TableBadgeItem } from '../../shared/components/TableBadgesCell/TableBadgesCell';

const OS_NAMES: Record<DevicePostureOsType, string> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
  ios: 'iOS',
  android: 'Android',
};

export const ALL_OS_TYPES: DevicePostureOsType[] = [
  'windows',
  'macos',
  'linux',
  'ios',
  'android',
];

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

export const systemItems = (posture: ApiDevicePosture): TableBadgeItem[] => {
  if (posture.os_rules.length === 0) {
    return [
      {
        key: 'any',
        label: m.posture_checks_any_system(),
        icon: 'globe',
        variant: 'neutral',
      },
    ];
  }
  return posture.os_rules.map((rule) => ({
    key: rule.os_type,
    label: osName(rule.os_type),
    variant: 'plan',
  }));
};

export const clientItems = (posture: ApiDevicePosture): TableBadgeItem[] => {
  const items: TableBadgeItem[] = [];
  if (posture.min_desktop_client_version) {
    items.push({
      key: 'desktop',
      label: `${m.posture_checks_desktop_client()} ${posture.min_desktop_client_version}`,
      variant: 'outlined',
    });
  }
  if (posture.min_mobile_client_version) {
    items.push({
      key: 'mobile',
      label: `${m.posture_checks_mobile_application()} ${posture.min_mobile_client_version}`,
      variant: 'outlined',
    });
  }
  if (posture.allow_prerelease_client) {
    items.push({
      key: 'prerelease',
      label: m.posture_checks_prerelease_badge(),
      variant: 'warning',
    });
  }
  if (items.length === 0) {
    return [{ key: 'any', label: m.posture_checks_version_any(), variant: 'neutral' }];
  }
  return items;
};

export const locationItems = (
  posture: ApiDevicePosture,
  names: Map<number, string>,
): TableBadgeItem[] =>
  posture.locations.map((id) => ({
    key: `loc-${id}`,
    label: names.get(id) ?? `#${id}`,
    icon: 'location',
  }));

export const postureSearchText = (
  posture: ApiDevicePosture,
  locationNames: Map<number, string>,
) =>
  [
    posture.name,
    posture.description ?? '',
    ...posture.os_rules.map((rule) => osName(rule.os_type)),
    posture.min_desktop_client_version ?? '',
    posture.min_mobile_client_version ?? '',
    ...posture.locations.map((id) => locationNames.get(id) ?? `#${id}`),
  ]
    .join('\n')
    .toLowerCase();
