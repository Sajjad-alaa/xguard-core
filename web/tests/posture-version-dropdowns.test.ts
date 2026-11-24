import { describe, expect, it } from 'vitest';
import {
  AGE_PRESETS,
  ageOptions,
  ageToChoice,
  CHOICE_ANY,
  CHOICE_CUSTOM,
  choiceToAge,
  choiceToVersion,
  versionOptions,
  versionToChoice,
} from '../src/pages/PostureChecksPage/modals/CEPostureCheckModal/choices';
import {
  emptyForm,
  formSchema,
  formToRequest,
  postureToForm,
} from '../src/pages/PostureChecksPage/modals/CEPostureCheckModal/form';
import type {
  ApiDevicePosture,
  DevicePostureVersionCatalog,
} from '../src/shared/api/types';

const catalog: DevicePostureVersionCatalog = {
  windows: [
    { value: '10.0.22631', label: 'Windows 11 23H2' },
    { value: '10.0.26100', label: 'Windows 11 24H2' },
  ],
  macos: [{ value: '15', label: 'macOS 15 Sequoia' }],
  ios: [{ value: '18', label: 'iOS 18' }],
  android: [{ value: '15', label: 'Android 15' }],
  linux_kernel: [{ value: '6.6', label: '6.6 LTS' }],
  desktop_client: [
    { value: '2.2.0', label: '2.2.0' },
    { value: '2.3.0', label: '2.3.0' },
    { value: '2.3.1', label: '2.3.1' },
  ],
  mobile_client: [
    { value: '2.2.0', label: '2.2.0' },
    { value: '2.3.0', label: '2.3.0' },
    { value: '2.3.1', label: '2.3.1' },
  ],
};

const labels = { any: 'Any version', custom: 'Custom…' };

describe('version dropdown mapping', () => {
  it('maps stored versions to Any, a catalog entry or Custom', () => {
    expect(versionToChoice(null, catalog.windows)).toEqual({
      choice: CHOICE_ANY,
      custom: null,
    });
    expect(versionToChoice('', catalog.windows).choice).toBe(CHOICE_ANY);
    expect(versionToChoice('10.0.26100', catalog.windows)).toEqual({
      choice: '10.0.26100',
      custom: null,
    });
    expect(versionToChoice('10.0.19041', catalog.windows)).toEqual({
      choice: CHOICE_CUSTOM,
      custom: '10.0.19041',
    });
  });

  it('maps dropdown choices back to the request value', () => {
    expect(choiceToVersion(CHOICE_ANY, 'ignored')).toBeNull();
    expect(choiceToVersion('10.0.26100', 'ignored')).toBe('10.0.26100');
    expect(choiceToVersion(CHOICE_CUSTOM, ' 10.0.19041 ')).toBe('10.0.19041');
    expect(choiceToVersion(CHOICE_CUSTOM, '   ')).toBeNull();
  });

  it('lists Any, the catalog labels and Custom', () => {
    const options = versionOptions(catalog.windows, labels);
    expect(options.map((option) => option.label)).toEqual([
      'Any version',
      'Windows 11 23H2',
      'Windows 11 24H2',
      'Custom…',
    ]);
    expect(options.map((option) => option.value)).toEqual([
      CHOICE_ANY,
      '10.0.22631',
      '10.0.26100',
      CHOICE_CUSTOM,
    ]);
  });
});

describe('day-count dropdown mapping', () => {
  it('offers Any, the presets and Custom', () => {
    const options = ageOptions({ ...labels, days: (days) => `${days} days` });
    expect(options.map((option) => option.value)).toEqual([
      CHOICE_ANY,
      '7',
      '14',
      '30',
      '60',
      '90',
      '180',
      CHOICE_CUSTOM,
    ]);
    expect(options[3].label).toBe('30 days');
    expect([...AGE_PRESETS]).toEqual([7, 14, 30, 60, 90, 180]);
  });

  it('maps stored ages both ways', () => {
    expect(ageToChoice(null)).toEqual({ choice: CHOICE_ANY, custom: null });
    expect(ageToChoice(30)).toEqual({ choice: '30', custom: null });
    expect(ageToChoice(45)).toEqual({ choice: CHOICE_CUSTOM, custom: 45 });
    expect(choiceToAge(CHOICE_ANY, 5)).toBeNull();
    expect(choiceToAge('90', null)).toBe(90);
    expect(choiceToAge(CHOICE_CUSTOM, 45)).toBe(45);
    expect(choiceToAge(CHOICE_CUSTOM, null)).toBeNull();
  });
});

const stored: ApiDevicePosture = {
  id: 7,
  name: 'All platforms',
  description: null,
  min_desktop_client_version: '2.3.1',
  min_mobile_client_version: '2.1.5',
  allow_prerelease_client: false,
  locations: [],
  os_rules: [
    {
      os_type: 'windows',
      min_os_version: '10.0.26100',
      disk_encryption_required: true,
      firewall_required: null,
      screen_lock_required: null,
      antivirus_required: true,
      ad_domain_joined_required: null,
      windows_security_update_max_age: 30,
    },
    {
      os_type: 'macos',
      min_os_version: '14.6',
      disk_encryption_required: null,
      firewall_required: null,
      screen_lock_required: null,
      device_integrity_required: null,
      antivirus_required: true,
      ad_domain_joined_required: true,
      security_update_max_age: 45,
    },
    {
      os_type: 'linux',
      min_kernel_version: '6.6',
      disk_encryption_required: null,
      firewall_required: null,
      screen_lock_required: null,
      antivirus_required: null,
      ad_domain_joined_required: true,
      security_update_max_age: 14,
    },
    {
      os_type: 'ios',
      min_os_version: null,
      screen_lock_required: true,
      disk_encryption_required: true,
    },
    {
      os_type: 'android',
      min_os_version: '15',
      device_integrity_required: null,
      android_security_patch_level_max_age: 120,
      screen_lock_required: true,
      disk_encryption_required: true,
    },
  ],
};

describe('editing a stored policy', () => {
  it('shows catalog values as choices and other values as Custom', () => {
    const form = postureToForm(stored, catalog);
    expect(form.min_desktop_client_version_choice).toBe('2.3.1');
    expect(form.min_desktop_client_version).toBeNull();
    expect(form.min_mobile_client_version_choice).toBe(CHOICE_CUSTOM);
    expect(form.min_mobile_client_version).toBe('2.1.5');
    expect(form.windows_version_choice).toBe('10.0.26100');
    expect(form.windows_update_age_choice).toBe('30');
    expect(form.macos_version_choice).toBe(CHOICE_CUSTOM);
    expect(form.macos_version).toBe('14.6');
    expect(form.macos_update_age_choice).toBe(CHOICE_CUSTOM);
    expect(form.macos_update_age).toBe(45);
    expect(form.macos_antivirus).toBe(true);
    expect(form.macos_domain).toBe(true);
    expect(form.linux_kernel_choice).toBe('6.6');
    expect(form.linux_update_age_choice).toBe('14');
    expect(form.linux_domain).toBe(true);
    expect(form.ios_version_choice).toBe(CHOICE_ANY);
    expect(form.ios_screen_lock).toBe(true);
    expect(form.ios_disk_encryption).toBe(true);
    expect(form.android_version_choice).toBe('15');
    expect(form.android_patch_age_choice).toBe(CHOICE_CUSTOM);
    expect(form.android_patch_age).toBe(120);
    expect(form.android_screen_lock).toBe(true);
    expect(form.android_disk_encryption).toBe(true);
    expect(formSchema.safeParse(form).success).toBe(true);
  });

  it('saves the stored policy unchanged', () => {
    const request = formToRequest(postureToForm(stored, catalog));
    expect(request.min_desktop_client_version).toBe('2.3.1');
    expect(request.min_mobile_client_version).toBe('2.1.5');
    expect(request.os_rules).toEqual(stored.os_rules);
  });

  it('without a catalog every stored value is Custom and still round-trips', () => {
    const form = postureToForm(stored);
    expect(form.windows_version_choice).toBe(CHOICE_CUSTOM);
    expect(form.windows_version).toBe('10.0.26100');
    expect(formToRequest(form).os_rules).toEqual(stored.os_rules);
  });

  it('switching from Custom to Any drops the requirement', () => {
    const form = postureToForm(stored, catalog);
    form.macos_version_choice = CHOICE_ANY;
    form.macos_update_age_choice = '90';
    const macos = formToRequest(form).os_rules.find((rule) => rule.os_type === 'macos');
    expect(macos).toMatchObject({ min_os_version: null, security_update_max_age: 90 });
  });

  it('a new policy starts with Any everywhere', () => {
    const form = emptyForm();
    form.name = 'New';
    form.linux = true;
    form.linux_antivirus = true;
    expect(formToRequest(form).os_rules).toEqual([
      {
        os_type: 'linux',
        min_kernel_version: null,
        disk_encryption_required: null,
        firewall_required: null,
        screen_lock_required: null,
        antivirus_required: true,
        ad_domain_joined_required: null,
        security_update_max_age: null,
      },
    ]);
  });
});
