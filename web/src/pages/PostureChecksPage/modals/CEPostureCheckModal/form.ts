import z from 'zod';
import { m } from '../../../../paraglide/messages';
import type {
  ApiDevicePosture,
  ApiDevicePostureOsRule,
  DevicePostureVersionCatalog,
  DevicePostureVersionOption,
  EditDevicePostureRequest,
} from '../../../../shared/api/types';
import { nameValidator } from '../../../../shared/validators';
import {
  ageToChoice,
  CHOICE_ANY,
  CHOICE_CUSTOM,
  choiceToAge,
  choiceToVersion,
  versionToChoice,
} from './choices';

/** A dotted version: 1 to 4 numbers, e.g. `14.5` or `10.0.22631`. */
export const DOTTED_VERSION = /^\d{1,5}(\.\d{1,5}){0,3}$/;
/** A client version, e.g. `2.2.0` or `2.3.0-beta1`. */
export const CLIENT_VERSION = /^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
export const MAX_AGE_DAYS = 3650;

/**
 * Version dropdowns: `<field>_choice` holds the dropdown value ("any", a catalog value or
 * "custom") and `<field>` the custom text, which is only used (and validated) for "custom".
 */
const VERSION_FIELDS = {
  min_desktop_client_version: CLIENT_VERSION,
  min_mobile_client_version: CLIENT_VERSION,
  windows_version: DOTTED_VERSION,
  macos_version: DOTTED_VERSION,
  linux_kernel: DOTTED_VERSION,
  ios_version: DOTTED_VERSION,
  android_version: DOTTED_VERSION,
} as const;
export type VersionField = keyof typeof VERSION_FIELDS;

/** Day-count dropdowns, same scheme as the versions. */
const AGE_FIELDS = [
  'windows_update_age',
  'macos_update_age',
  'linux_update_age',
  'android_patch_age',
] as const;
export type AgeField = (typeof AGE_FIELDS)[number];

const choice = z.string();
const customText = z.string().max(64).nullable();
const customAge = z.number().nullable();

export const formSchema = z
  .object({
    name: z.string().trim().min(1, m.form_error_required()).max(64).pipe(nameValidator),
    description: z.string().max(512).nullable(),
    min_desktop_client_version_choice: choice,
    min_desktop_client_version: customText,
    min_mobile_client_version_choice: choice,
    min_mobile_client_version: customText,
    allow_prerelease_client: z.boolean(),
    locations: z.array(z.number()),
    windows: z.boolean(),
    windows_version_choice: choice,
    windows_version: customText,
    windows_disk_encryption: z.boolean(),
    windows_firewall: z.boolean(),
    windows_screen_lock: z.boolean(),
    windows_antivirus: z.boolean(),
    windows_domain: z.boolean(),
    windows_update_age_choice: choice,
    windows_update_age: customAge,
    macos: z.boolean(),
    macos_version_choice: choice,
    macos_version: customText,
    macos_disk_encryption: z.boolean(),
    macos_firewall: z.boolean(),
    macos_screen_lock: z.boolean(),
    macos_integrity: z.boolean(),
    macos_antivirus: z.boolean(),
    macos_domain: z.boolean(),
    macos_update_age_choice: choice,
    macos_update_age: customAge,
    linux: z.boolean(),
    linux_kernel_choice: choice,
    linux_kernel: customText,
    linux_disk_encryption: z.boolean(),
    linux_firewall: z.boolean(),
    linux_screen_lock: z.boolean(),
    linux_antivirus: z.boolean(),
    linux_domain: z.boolean(),
    linux_update_age_choice: choice,
    linux_update_age: customAge,
    ios: z.boolean(),
    ios_version_choice: choice,
    ios_version: customText,
    ios_screen_lock: z.boolean(),
    ios_disk_encryption: z.boolean(),
    android: z.boolean(),
    android_version_choice: choice,
    android_version: customText,
    android_integrity: z.boolean(),
    android_screen_lock: z.boolean(),
    android_disk_encryption: z.boolean(),
    android_patch_age_choice: choice,
    android_patch_age: customAge,
  })
  .superRefine((values, ctx) => {
    for (const [field, pattern] of Object.entries(VERSION_FIELDS) as [
      VersionField,
      RegExp,
    ][]) {
      if (values[`${field}_choice`] !== CHOICE_CUSTOM) continue;
      const text = values[field]?.trim() ?? '';
      if (text.length === 0) {
        ctx.addIssue({ code: 'custom', path: [field], message: m.form_error_required() });
      } else if (!pattern.test(text)) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: m.posture_checks_form_error_version(),
        });
      }
    }
    for (const field of AGE_FIELDS) {
      if (values[`${field}_choice`] !== CHOICE_CUSTOM) continue;
      const days = values[field];
      if (days === null || !Number.isInteger(days) || days < 1 || days > MAX_AGE_DAYS) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: m.posture_checks_form_error_age({ max: MAX_AGE_DAYS }),
        });
      }
    }
  });

export type FormFields = z.infer<typeof formSchema>;

export const emptyForm = (): FormFields => ({
  name: '',
  description: null,
  min_desktop_client_version_choice: CHOICE_ANY,
  min_desktop_client_version: null,
  min_mobile_client_version_choice: CHOICE_ANY,
  min_mobile_client_version: null,
  allow_prerelease_client: false,
  locations: [],
  windows: false,
  windows_version_choice: CHOICE_ANY,
  windows_version: null,
  windows_disk_encryption: false,
  windows_firewall: false,
  windows_screen_lock: false,
  windows_antivirus: false,
  windows_domain: false,
  windows_update_age_choice: CHOICE_ANY,
  windows_update_age: null,
  macos: false,
  macos_version_choice: CHOICE_ANY,
  macos_version: null,
  macos_disk_encryption: false,
  macos_firewall: false,
  macos_screen_lock: false,
  macos_integrity: false,
  macos_antivirus: false,
  macos_domain: false,
  macos_update_age_choice: CHOICE_ANY,
  macos_update_age: null,
  linux: false,
  linux_kernel_choice: CHOICE_ANY,
  linux_kernel: null,
  linux_disk_encryption: false,
  linux_firewall: false,
  linux_screen_lock: false,
  linux_antivirus: false,
  linux_domain: false,
  linux_update_age_choice: CHOICE_ANY,
  linux_update_age: null,
  ios: false,
  ios_version_choice: CHOICE_ANY,
  ios_version: null,
  ios_screen_lock: false,
  ios_disk_encryption: false,
  android: false,
  android_version_choice: CHOICE_ANY,
  android_version: null,
  android_integrity: false,
  android_screen_lock: false,
  android_disk_encryption: false,
  android_patch_age_choice: CHOICE_ANY,
  android_patch_age: null,
});

/** Puts a stored value into its dropdown: a catalog entry, or "custom" with the value. */
const setVersion = (
  form: FormFields,
  field: VersionField,
  value: string | null | undefined,
  options: readonly DevicePostureVersionOption[] | undefined,
) => {
  const { choice, custom } = versionToChoice(value, options ?? []);
  form[`${field}_choice`] = choice;
  form[field] = custom;
};

const setAge = (form: FormFields, field: AgeField, value: number | null | undefined) => {
  const { choice, custom } = ageToChoice(value);
  form[`${field}_choice`] = choice;
  form[field] = custom;
};

/**
 * The form for a stored policy. `versions` decides which stored versions show as a catalog
 * entry; any other value shows as "custom" with the value filled in.
 */
export const postureToForm = (
  posture: ApiDevicePosture,
  versions?: Partial<DevicePostureVersionCatalog>,
): FormFields => {
  const form = emptyForm();
  form.name = posture.name;
  form.description = posture.description;
  setVersion(
    form,
    'min_desktop_client_version',
    posture.min_desktop_client_version,
    versions?.desktop_client,
  );
  setVersion(
    form,
    'min_mobile_client_version',
    posture.min_mobile_client_version,
    versions?.mobile_client,
  );
  form.allow_prerelease_client = posture.allow_prerelease_client;
  form.locations = [...posture.locations];
  for (const rule of posture.os_rules) {
    switch (rule.os_type) {
      case 'windows':
        form.windows = true;
        setVersion(form, 'windows_version', rule.min_os_version, versions?.windows);
        form.windows_disk_encryption = rule.disk_encryption_required === true;
        form.windows_firewall = rule.firewall_required === true;
        form.windows_screen_lock = rule.screen_lock_required === true;
        form.windows_antivirus = rule.antivirus_required === true;
        form.windows_domain = rule.ad_domain_joined_required === true;
        setAge(form, 'windows_update_age', rule.windows_security_update_max_age);
        break;
      case 'macos':
        form.macos = true;
        setVersion(form, 'macos_version', rule.min_os_version, versions?.macos);
        form.macos_disk_encryption = rule.disk_encryption_required === true;
        form.macos_firewall = rule.firewall_required === true;
        form.macos_screen_lock = rule.screen_lock_required === true;
        form.macos_integrity = rule.device_integrity_required === true;
        form.macos_antivirus = rule.antivirus_required === true;
        form.macos_domain = rule.ad_domain_joined_required === true;
        setAge(form, 'macos_update_age', rule.security_update_max_age);
        break;
      case 'linux':
        form.linux = true;
        setVersion(form, 'linux_kernel', rule.min_kernel_version, versions?.linux_kernel);
        form.linux_disk_encryption = rule.disk_encryption_required === true;
        form.linux_firewall = rule.firewall_required === true;
        form.linux_screen_lock = rule.screen_lock_required === true;
        form.linux_antivirus = rule.antivirus_required === true;
        form.linux_domain = rule.ad_domain_joined_required === true;
        setAge(form, 'linux_update_age', rule.security_update_max_age);
        break;
      case 'ios':
        form.ios = true;
        setVersion(form, 'ios_version', rule.min_os_version, versions?.ios);
        form.ios_screen_lock = rule.screen_lock_required === true;
        form.ios_disk_encryption = rule.disk_encryption_required === true;
        break;
      case 'android':
        form.android = true;
        setVersion(form, 'android_version', rule.min_os_version, versions?.android);
        form.android_integrity = rule.device_integrity_required === true;
        form.android_screen_lock = rule.screen_lock_required === true;
        form.android_disk_encryption = rule.disk_encryption_required === true;
        setAge(form, 'android_patch_age', rule.android_security_patch_level_max_age);
        break;
    }
  }
  return form;
};

const text = (value: string | null) => {
  const trimmed = value?.trim() ?? '';
  return trimmed.length > 0 ? trimmed : null;
};

/** `true` only when required; `null` otherwise, so unchecked boxes are not stored. */
const flag = (value: boolean) => (value ? true : null);

const version = (values: FormFields, field: VersionField) =>
  choiceToVersion(values[`${field}_choice`], values[field]);

const age = (values: FormFields, field: AgeField) =>
  choiceToAge(values[`${field}_choice`], values[field]);

export const formToRequest = (values: FormFields): EditDevicePostureRequest => {
  const os_rules: ApiDevicePostureOsRule[] = [];
  if (values.windows) {
    os_rules.push({
      os_type: 'windows',
      min_os_version: version(values, 'windows_version'),
      disk_encryption_required: flag(values.windows_disk_encryption),
      firewall_required: flag(values.windows_firewall),
      screen_lock_required: flag(values.windows_screen_lock),
      antivirus_required: flag(values.windows_antivirus),
      ad_domain_joined_required: flag(values.windows_domain),
      windows_security_update_max_age: age(values, 'windows_update_age'),
    });
  }
  if (values.macos) {
    os_rules.push({
      os_type: 'macos',
      min_os_version: version(values, 'macos_version'),
      disk_encryption_required: flag(values.macos_disk_encryption),
      firewall_required: flag(values.macos_firewall),
      screen_lock_required: flag(values.macos_screen_lock),
      device_integrity_required: flag(values.macos_integrity),
      antivirus_required: flag(values.macos_antivirus),
      ad_domain_joined_required: flag(values.macos_domain),
      security_update_max_age: age(values, 'macos_update_age'),
    });
  }
  if (values.linux) {
    os_rules.push({
      os_type: 'linux',
      min_kernel_version: version(values, 'linux_kernel'),
      disk_encryption_required: flag(values.linux_disk_encryption),
      firewall_required: flag(values.linux_firewall),
      screen_lock_required: flag(values.linux_screen_lock),
      antivirus_required: flag(values.linux_antivirus),
      ad_domain_joined_required: flag(values.linux_domain),
      security_update_max_age: age(values, 'linux_update_age'),
    });
  }
  if (values.ios) {
    os_rules.push({
      os_type: 'ios',
      min_os_version: version(values, 'ios_version'),
      screen_lock_required: flag(values.ios_screen_lock),
      disk_encryption_required: flag(values.ios_disk_encryption),
    });
  }
  if (values.android) {
    os_rules.push({
      os_type: 'android',
      min_os_version: version(values, 'android_version'),
      device_integrity_required: flag(values.android_integrity),
      android_security_patch_level_max_age: age(values, 'android_patch_age'),
      screen_lock_required: flag(values.android_screen_lock),
      disk_encryption_required: flag(values.android_disk_encryption),
    });
  }
  return {
    name: values.name.trim(),
    description: text(values.description),
    min_desktop_client_version: version(values, 'min_desktop_client_version'),
    min_mobile_client_version: version(values, 'min_mobile_client_version'),
    allow_prerelease_client: values.allow_prerelease_client,
    os_rules,
  };
};
