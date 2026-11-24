import { describe, expect, it } from 'vitest';
import {
  emptyForm,
  formSchema,
  formToRequest,
  postureToForm,
} from '../src/pages/PostureChecksPage/modals/CEPostureCheckModal/form';
import {
  clientSummary,
  locationsSummary,
  systemsSummary,
} from '../src/pages/PostureChecksPage/summary';
import type { ApiDevicePosture } from '../src/shared/api/types';
import { factRows } from '../src/shared/components/modals/DevicePostureModal/facts';

const posture: ApiDevicePosture = {
  id: 3,
  name: 'Laptops',
  description: 'Company laptops',
  min_desktop_client_version: '2.2.0',
  min_mobile_client_version: null,
  allow_prerelease_client: false,
  os_rules: [
    {
      os_type: 'windows',
      min_os_version: '10.0.22631',
      disk_encryption_required: true,
      firewall_required: true,
      screen_lock_required: null,
      antivirus_required: null,
      ad_domain_joined_required: true,
      windows_security_update_max_age: 30,
    },
    {
      os_type: 'linux',
      min_kernel_version: '6.1',
      disk_encryption_required: true,
      firewall_required: null,
      screen_lock_required: true,
      antivirus_required: null,
      ad_domain_joined_required: null,
      security_update_max_age: null,
    },
  ],
  locations: [1, 2],
};

describe('posture policy form', () => {
  it('round-trips a policy through the form', () => {
    const form = postureToForm(posture);
    expect(form.windows).toBe(true);
    expect(form.linux).toBe(true);
    expect(form.macos).toBe(false);
    expect(form.windows_version).toBe('10.0.22631');
    expect(form.locations).toEqual([1, 2]);
    expect(formSchema.safeParse(form).success).toBe(true);
    const request = formToRequest(form);
    expect(request.name).toBe('Laptops');
    expect(request.os_rules).toEqual(posture.os_rules);
  });

  it('sends only enabled systems and trims empty values', () => {
    const form = emptyForm();
    form.name = '  Office ';
    form.description = '   ';
    form.macos = true;
    form.macos_version_choice = 'custom';
    form.macos_version = ' 14.5 ';
    form.macos_firewall = true;
    form.linux_disk_encryption = true; // ignored: Linux is not enabled
    const request = formToRequest(form);
    expect(request.name).toBe('Office');
    expect(request.description).toBeNull();
    expect(request.os_rules).toEqual([
      {
        os_type: 'macos',
        min_os_version: '14.5',
        disk_encryption_required: null,
        firewall_required: true,
        screen_lock_required: null,
        device_integrity_required: null,
        antivirus_required: null,
        ad_domain_joined_required: null,
        security_update_max_age: null,
      },
    ]);
  });

  it('rejects malformed versions and ages', () => {
    const valid = { ...emptyForm(), name: 'Valid' };
    expect(formSchema.safeParse(valid).success).toBe(true);
    for (const bad of [
      { windows_version_choice: 'custom', windows_version: '11 23H2' },
      { linux_kernel_choice: 'custom', linux_kernel: '6.x' },
      { min_desktop_client_version_choice: 'custom', min_desktop_client_version: '2.2' },
      { windows_update_age_choice: 'custom', windows_update_age: 0 },
      { android_patch_age_choice: 'custom', android_patch_age: 4000 },
      { macos_update_age_choice: 'custom', macos_update_age: null },
      { ios_version_choice: 'custom', ios_version: '  ' },
      { name: '' },
    ]) {
      expect(
        formSchema.safeParse({ ...valid, ...bad }).success,
        JSON.stringify(bad),
      ).toBe(false);
    }
    expect(
      formSchema.safeParse({
        ...valid,
        min_desktop_client_version_choice: 'custom',
        min_desktop_client_version: '2.3.0-beta1',
      }).success,
    ).toBe(true);
    // A leftover custom value is ignored once another choice is picked.
    expect(
      formSchema.safeParse({
        ...valid,
        windows_version_choice: 'any',
        windows_version: 'garbage',
      }).success,
    ).toBe(true);
  });

  it('summarises policies for the table', () => {
    expect(systemsSummary(posture)).toBe('Windows, Linux');
    expect(systemsSummary({ ...posture, os_rules: [] })).toBe('Any system');
    expect(clientSummary(posture)).toBe('2.2.0');
    expect(locationsSummary(posture, new Map([[1, 'Office']]))).toBe('Office, #2');
    expect(locationsSummary({ ...posture, locations: [] }, new Map())).toBe(
      'Not assigned',
    );
  });
});

describe('device posture facts', () => {
  it('shows unknown facts as unknown, never as compliant', () => {
    const rows = factRows({ os: 'linux', kernel_version: '6.8.0', disk_encrypted: true });
    const byLabel = Object.fromEntries(rows.map((row) => [row.label, row.value]));
    expect(byLabel['Disk encryption']).toBe('Yes');
    expect(byLabel.Firewall).toBe('Unknown');
    expect(byLabel.Kernel).toBe('6.8.0');
    // Linux reports antivirus, domain and update age too now.
    expect(byLabel.Antivirus).toBe('Unknown');
    const ios = factRows({ os: 'ios', screen_lock_enabled: true, disk_encrypted: true });
    const iosLabels = ios.map((row) => row.label);
    expect(iosLabels).not.toContain('Firewall');
    expect(iosLabels).not.toContain('Antivirus');
    expect(ios.find((row) => row.label === 'Screen lock')?.value).toBe('Yes');
    const android = factRows({ os: 'android', security_patch_date: '2026-10-05' });
    expect(android.find((row) => row.label === 'Security patch level')?.value).toBe(
      '2026-10-05',
    );
    const windows = factRows({ os: 'windows', antivirus_enabled: false });
    expect(windows.find((row) => row.label === 'Antivirus')?.value).toBe('No');
  });
});
