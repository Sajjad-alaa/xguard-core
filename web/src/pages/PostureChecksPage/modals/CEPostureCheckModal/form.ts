import z from 'zod';
import { m } from '../../../../paraglide/messages';
import type {
  ApiDevicePosture,
  ApiDevicePostureOsRule,
  EditDevicePostureRequest,
} from '../../../../shared/api/types';
import { nameValidator } from '../../../../shared/validators';

/** A dotted version: 1 to 4 numbers, e.g. `14.5` or `10.0.22631`. */
export const DOTTED_VERSION = /^\d{1,5}(\.\d{1,5}){0,3}$/;
/** A client version, e.g. `2.2.0` or `2.3.0-beta1`. */
export const CLIENT_VERSION = /^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
export const MAX_AGE_DAYS = 3650;

const optionalText = (pattern: RegExp) =>
  z
    .string()
    .trim()
    .max(64)
    .nullable()
    .refine((value) => !value || pattern.test(value), {
      message: m.posture_checks_form_error_version(),
    });

const optionalAge = z
  .number()
  .int()
  .min(1, m.posture_checks_form_error_age({ max: MAX_AGE_DAYS }))
  .max(MAX_AGE_DAYS, m.posture_checks_form_error_age({ max: MAX_AGE_DAYS }))
  .nullable();

export const formSchema = z.object({
  name: z.string().trim().min(1, m.form_error_required()).max(64).pipe(nameValidator),
  description: z.string().max(512).nullable(),
  min_desktop_client_version: optionalText(CLIENT_VERSION),
  min_mobile_client_version: optionalText(CLIENT_VERSION),
  allow_prerelease_client: z.boolean(),
  locations: z.array(z.number()),
  windows: z.boolean(),
  windows_version: optionalText(DOTTED_VERSION),
  windows_disk_encryption: z.boolean(),
  windows_firewall: z.boolean(),
  windows_screen_lock: z.boolean(),
  windows_antivirus: z.boolean(),
  windows_domain: z.boolean(),
  windows_update_age: optionalAge,
  macos: z.boolean(),
  macos_version: optionalText(DOTTED_VERSION),
  macos_disk_encryption: z.boolean(),
  macos_firewall: z.boolean(),
  macos_screen_lock: z.boolean(),
  macos_integrity: z.boolean(),
  linux: z.boolean(),
  linux_kernel: optionalText(DOTTED_VERSION),
  linux_disk_encryption: z.boolean(),
  linux_firewall: z.boolean(),
  linux_screen_lock: z.boolean(),
  ios: z.boolean(),
  ios_version: optionalText(DOTTED_VERSION),
  android: z.boolean(),
  android_version: optionalText(DOTTED_VERSION),
  android_integrity: z.boolean(),
  android_patch_age: optionalAge,
});

export type FormFields = z.infer<typeof formSchema>;

export const emptyForm = (): FormFields => ({
  name: '',
  description: null,
  min_desktop_client_version: null,
  min_mobile_client_version: null,
  allow_prerelease_client: false,
  locations: [],
  windows: false,
  windows_version: null,
  windows_disk_encryption: false,
  windows_firewall: false,
  windows_screen_lock: false,
  windows_antivirus: false,
  windows_domain: false,
  windows_update_age: null,
  macos: false,
  macos_version: null,
  macos_disk_encryption: false,
  macos_firewall: false,
  macos_screen_lock: false,
  macos_integrity: false,
  linux: false,
  linux_kernel: null,
  linux_disk_encryption: false,
  linux_firewall: false,
  linux_screen_lock: false,
  ios: false,
  ios_version: null,
  android: false,
  android_version: null,
  android_integrity: false,
  android_patch_age: null,
});

export const postureToForm = (posture: ApiDevicePosture): FormFields => {
  const form = emptyForm();
  form.name = posture.name;
  form.description = posture.description;
  form.min_desktop_client_version = posture.min_desktop_client_version;
  form.min_mobile_client_version = posture.min_mobile_client_version;
  form.allow_prerelease_client = posture.allow_prerelease_client;
  form.locations = [...posture.locations];
  for (const rule of posture.os_rules) {
    switch (rule.os_type) {
      case 'windows':
        form.windows = true;
        form.windows_version = rule.min_os_version;
        form.windows_disk_encryption = rule.disk_encryption_required === true;
        form.windows_firewall = rule.firewall_required === true;
        form.windows_screen_lock = rule.screen_lock_required === true;
        form.windows_antivirus = rule.antivirus_required === true;
        form.windows_domain = rule.ad_domain_joined_required === true;
        form.windows_update_age = rule.windows_security_update_max_age;
        break;
      case 'macos':
        form.macos = true;
        form.macos_version = rule.min_os_version;
        form.macos_disk_encryption = rule.disk_encryption_required === true;
        form.macos_firewall = rule.firewall_required === true;
        form.macos_screen_lock = rule.screen_lock_required === true;
        form.macos_integrity = rule.device_integrity_required === true;
        break;
      case 'linux':
        form.linux = true;
        form.linux_kernel = rule.min_kernel_version;
        form.linux_disk_encryption = rule.disk_encryption_required === true;
        form.linux_firewall = rule.firewall_required === true;
        form.linux_screen_lock = rule.screen_lock_required === true;
        break;
      case 'ios':
        form.ios = true;
        form.ios_version = rule.min_os_version;
        break;
      case 'android':
        form.android = true;
        form.android_version = rule.min_os_version;
        form.android_integrity = rule.device_integrity_required === true;
        form.android_patch_age = rule.android_security_patch_level_max_age;
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

export const formToRequest = (values: FormFields): EditDevicePostureRequest => {
  const os_rules: ApiDevicePostureOsRule[] = [];
  if (values.windows) {
    os_rules.push({
      os_type: 'windows',
      min_os_version: text(values.windows_version),
      disk_encryption_required: flag(values.windows_disk_encryption),
      firewall_required: flag(values.windows_firewall),
      screen_lock_required: flag(values.windows_screen_lock),
      antivirus_required: flag(values.windows_antivirus),
      ad_domain_joined_required: flag(values.windows_domain),
      windows_security_update_max_age: values.windows_update_age,
    });
  }
  if (values.macos) {
    os_rules.push({
      os_type: 'macos',
      min_os_version: text(values.macos_version),
      disk_encryption_required: flag(values.macos_disk_encryption),
      firewall_required: flag(values.macos_firewall),
      screen_lock_required: flag(values.macos_screen_lock),
      device_integrity_required: flag(values.macos_integrity),
    });
  }
  if (values.linux) {
    os_rules.push({
      os_type: 'linux',
      min_kernel_version: text(values.linux_kernel),
      disk_encryption_required: flag(values.linux_disk_encryption),
      firewall_required: flag(values.linux_firewall),
      screen_lock_required: flag(values.linux_screen_lock),
    });
  }
  if (values.ios) {
    os_rules.push({ os_type: 'ios', min_os_version: text(values.ios_version) });
  }
  if (values.android) {
    os_rules.push({
      os_type: 'android',
      min_os_version: text(values.android_version),
      device_integrity_required: flag(values.android_integrity),
      android_security_patch_level_max_age: values.android_patch_age,
    });
  }
  return {
    name: values.name.trim(),
    description: text(values.description),
    min_desktop_client_version: text(values.min_desktop_client_version),
    min_mobile_client_version: text(values.min_mobile_client_version),
    allow_prerelease_client: values.allow_prerelease_client,
    os_rules,
  };
};
