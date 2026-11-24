import type { DevicePostureVersionOption } from '../../../../shared/api/types';
import type { SelectOption } from '../../../../shared/xguard-ui/components/Select/types';

/**
 * Dropdown choices for versions and day counts.
 *
 * A requirement is shown as a dropdown with "Any" (no requirement), the suggested values and
 * "Custom…", which reveals a text input. A stored value that is not one of the suggestions is
 * shown as "Custom…" with the value filled in, so editing never loses a requirement.
 */

/** No requirement. */
export const CHOICE_ANY = 'any';
/** A value typed by the admin. */
export const CHOICE_CUSTOM = 'custom';

/** Day counts offered for update and patch ages. */
export const AGE_PRESETS = [7, 14, 30, 60, 90, 180] as const;

export type Choice<T> = { choice: string; custom: T | null };

/** The dropdown state for a stored version. */
export const versionToChoice = (
  value: string | null | undefined,
  options: readonly DevicePostureVersionOption[],
): Choice<string> => {
  const trimmed = value?.trim() ?? '';
  if (trimmed.length === 0) return { choice: CHOICE_ANY, custom: null };
  if (options.some((option) => option.value === trimmed)) {
    return { choice: trimmed, custom: null };
  }
  return { choice: CHOICE_CUSTOM, custom: trimmed };
};

/** The version to send for a dropdown state; `null` means no requirement. */
export const choiceToVersion = (choice: string, custom: string | null): string | null => {
  if (choice === CHOICE_ANY) return null;
  if (choice === CHOICE_CUSTOM) {
    const trimmed = custom?.trim() ?? '';
    return trimmed.length > 0 ? trimmed : null;
  }
  return choice;
};

/** The dropdown state for a stored day count. */
export const ageToChoice = (value: number | null | undefined): Choice<number> => {
  if (value === null || value === undefined) return { choice: CHOICE_ANY, custom: null };
  if ((AGE_PRESETS as readonly number[]).includes(value)) {
    return { choice: String(value), custom: null };
  }
  return { choice: CHOICE_CUSTOM, custom: value };
};

/** The day count to send for a dropdown state; `null` means no requirement. */
export const choiceToAge = (choice: string, custom: number | null): number | null => {
  if (choice === CHOICE_ANY) return null;
  if (choice === CHOICE_CUSTOM) return custom;
  const days = Number(choice);
  return Number.isInteger(days) ? days : null;
};

type Labels = { any: string; custom: string };

/** Dropdown options for a version list: Any, the catalog entries, Custom. */
export const versionOptions = (
  options: readonly DevicePostureVersionOption[],
  labels: Labels,
): SelectOption<string>[] => [
  { key: CHOICE_ANY, value: CHOICE_ANY, label: labels.any },
  ...options.map((option) => ({
    key: option.value,
    value: option.value,
    label: option.label,
  })),
  { key: CHOICE_CUSTOM, value: CHOICE_CUSTOM, label: labels.custom },
];

/** Dropdown options for a day count: Any, the presets, Custom. */
export const ageOptions = (
  labels: Labels & { days: (days: number) => string },
): SelectOption<string>[] => [
  { key: CHOICE_ANY, value: CHOICE_ANY, label: labels.any },
  ...AGE_PRESETS.map((days) => ({
    key: String(days),
    value: String(days),
    label: labels.days(days),
  })),
  { key: CHOICE_CUSTOM, value: CHOICE_CUSTOM, label: labels.custom },
];
