import { m } from '../../../../paraglide/messages';
import type { DevicePostureFacts } from '../../../api/types';

export type FactRow = { label: string; value: string };

const flag = (value: boolean | null | undefined) =>
  value === true
    ? m.posture_device_fact_yes()
    : value === false
      ? m.posture_device_fact_no()
      : m.posture_device_fact_unknown();

const text = (value: string | number | null | undefined) =>
  value === null || value === undefined || value === ''
    ? m.posture_device_fact_unknown()
    : String(value);

/** Readable rows for the facts a client reported. */
export const factRows = (facts: Partial<DevicePostureFacts>): FactRow[] => [
  { label: m.posture_device_fact_os(), value: text(facts.os_name ?? facts.os) },
  { label: m.posture_device_fact_os_version(), value: text(facts.os_version) },
  ...(facts.kernel_version
    ? [{ label: m.posture_device_fact_kernel(), value: facts.kernel_version }]
    : []),
  { label: m.posture_device_fact_client(), value: text(facts.client_version) },
  { label: m.posture_device_fact_disk(), value: flag(facts.disk_encrypted) },
  { label: m.posture_device_fact_firewall(), value: flag(facts.firewall_enabled) },
  { label: m.posture_device_fact_screen_lock(), value: flag(facts.screen_lock_enabled) },
  ...(facts.os === 'windows'
    ? [
        {
          label: m.posture_device_fact_antivirus(),
          value: flag(facts.antivirus_enabled),
        },
        { label: m.posture_device_fact_domain(), value: flag(facts.domain_joined) },
        {
          label: m.posture_device_fact_update_age(),
          value: text(facts.security_update_age_days),
        },
      ]
    : []),
  ...(facts.os === 'macos' || facts.os === 'android'
    ? [{ label: m.posture_device_fact_integrity(), value: flag(facts.device_integrity) }]
    : []),
];
