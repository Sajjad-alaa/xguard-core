import z from 'zod';
import { m } from '../../../paraglide/messages';
import {
  DirectorySyncBehavior,
  type DirectorySyncBehaviorValue,
  DirectorySyncTarget,
  type DirectorySyncTargetValue,
  type ExternalOpenIdProvider,
  type ExternalOpenIdProviderInput,
  OpenIdProviderKind,
  type OpenIdProviderKindValue,
} from '../../../shared/api/types';
import { joinCsv, splitCsv } from '../../../shared/utils/csv';
import { nameValidator } from '../../../shared/validators';

/** Well-known issuers, filled in when a provider kind is picked. */
export const knownIssuers: Partial<Record<OpenIdProviderKindValue, string>> = {
  Google: 'https://accounts.google.com',
};

/** Provider kinds whose directory XGuard can sync with. */
export const directorySyncKinds: OpenIdProviderKindValue[] = [
  OpenIdProviderKind.Google,
  OpenIdProviderKind.Microsoft,
  OpenIdProviderKind.Okta,
  OpenIdProviderKind.JumpCloud,
];

export const supportsDirectorySync = (kind: OpenIdProviderKindValue) =>
  directorySyncKinds.includes(kind);

export const minimumSyncInterval = 60;

export const formSchema = z
  .object({
    kind: z.enum(Object.values(OpenIdProviderKind) as [OpenIdProviderKindValue]),
    issuer: z
      .string()
      .trim()
      .min(1, m.form_error_required())
      .refine((value) => URL.canParse(value), m.form_error_invalid()),
    client_id: z.string().trim().min(1, m.form_error_required()),
    client_secret: z.string(),
    display_name: z
      .string()
      .trim()
      .max(64)
      .refine((value) => value === '' || nameValidator.safeParse(value).success, {
        message: m.form_error_forbidden_char(),
      }),
    enabled: z.boolean(),
    disable_password_management: z.boolean(),
    create_accounts: z.boolean(),
    directory_sync_enabled: z.boolean(),
    directory_sync_interval: z.number(m.form_error_required()),
    directory_sync_target: z.enum(
      Object.values(DirectorySyncTarget) as [DirectorySyncTargetValue],
    ),
    directory_sync_user_behavior: z.enum(
      Object.values(DirectorySyncBehavior) as [DirectorySyncBehaviorValue],
    ),
    directory_sync_admin_behavior: z.enum(
      Object.values(DirectorySyncBehavior) as [DirectorySyncBehaviorValue],
    ),
    directory_sync_group_match: z.string(),
    directory_sync_user_groups: z.string(),
    prefetch_users: z.boolean(),
    admin_email: z
      .string()
      .trim()
      .refine((value) => value === '' || z.email().safeParse(value).success, {
        message: m.form_error_email(),
      }),
    google_service_account_key: z.string(),
    okta_dirsync_client_id: z.string().trim(),
    okta_private_jwk: z.string(),
    jumpcloud_api_key: z.string(),
  })
  .superRefine((value, ctx) => {
    if (!value.directory_sync_enabled) return;
    if (!supportsDirectorySync(value.kind)) {
      ctx.addIssue({
        code: 'custom',
        path: ['directory_sync_enabled'],
        message: m.settings_openid_sync_unsupported(),
      });
    }
    if (
      !Number.isInteger(value.directory_sync_interval) ||
      value.directory_sync_interval < minimumSyncInterval
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['directory_sync_interval'],
        message: m.form_error_min({ value: minimumSyncInterval }),
      });
    }
    if (value.kind === OpenIdProviderKind.Google && value.admin_email === '') {
      ctx.addIssue({
        code: 'custom',
        path: ['admin_email'],
        message: m.form_error_required(),
      });
    }
    if (value.kind === OpenIdProviderKind.Okta && value.okta_dirsync_client_id === '') {
      ctx.addIssue({
        code: 'custom',
        path: ['okta_dirsync_client_id'],
        message: m.form_error_required(),
      });
    }
  });

export type FormFields = z.infer<typeof formSchema>;

export const toForm = (
  provider: ExternalOpenIdProvider | null,
  createAccounts: boolean,
): FormFields => ({
  kind: provider?.kind ?? OpenIdProviderKind.Custom,
  issuer: provider?.issuer ?? '',
  client_id: provider?.client_id ?? '',
  client_secret: '',
  display_name: provider?.display_name ?? '',
  enabled: provider?.enabled ?? true,
  disable_password_management: provider?.disable_password_management ?? false,
  create_accounts: createAccounts,
  directory_sync_enabled: provider?.directory_sync_enabled ?? false,
  directory_sync_interval: provider?.directory_sync_interval ?? 600,
  directory_sync_target: provider?.directory_sync_target ?? DirectorySyncTarget.All,
  directory_sync_user_behavior:
    provider?.directory_sync_user_behavior ?? DirectorySyncBehavior.Keep,
  directory_sync_admin_behavior:
    provider?.directory_sync_admin_behavior ?? DirectorySyncBehavior.Keep,
  directory_sync_group_match: joinCsv(provider?.directory_sync_group_match),
  directory_sync_user_groups: joinCsv(provider?.directory_sync_user_groups),
  prefetch_users: provider?.prefetch_users ?? false,
  admin_email: provider?.admin_email ?? '',
  google_service_account_key: '',
  okta_dirsync_client_id: provider?.okta_dirsync_client_id ?? '',
  okta_private_jwk: '',
  jumpcloud_api_key: '',
});

const secret = (value: string) => (value.trim() === '' ? undefined : value.trim());
const optional = (value: string) => (value.trim() === '' ? null : value.trim());

/** Empty secret fields keep the stored secrets. */
export const toInput = (value: FormFields): ExternalOpenIdProviderInput => ({
  kind: value.kind,
  issuer: value.issuer.trim(),
  client_id: value.client_id.trim(),
  client_secret: secret(value.client_secret),
  enabled: value.enabled,
  display_name: optional(value.display_name),
  disable_password_management: value.disable_password_management,
  directory_sync_enabled: value.directory_sync_enabled,
  directory_sync_interval: value.directory_sync_interval,
  directory_sync_target: value.directory_sync_target,
  directory_sync_user_behavior: value.directory_sync_user_behavior,
  directory_sync_admin_behavior: value.directory_sync_admin_behavior,
  directory_sync_group_match: splitCsv(value.directory_sync_group_match),
  directory_sync_user_groups: splitCsv(value.directory_sync_user_groups),
  prefetch_users: value.prefetch_users,
  admin_email: optional(value.admin_email),
  google_service_account_key: secret(value.google_service_account_key),
  okta_dirsync_client_id: optional(value.okta_dirsync_client_id),
  okta_private_jwk: secret(value.okta_private_jwk),
  jumpcloud_api_key: secret(value.jumpcloud_api_key),
});

/** Whether the secret a provider kind needs for directory sync is stored. */
export const directorySecretStored = (
  provider: ExternalOpenIdProvider | null,
  kind: OpenIdProviderKindValue,
): boolean => {
  if (!provider || provider.kind !== kind) return false;
  switch (kind) {
    case OpenIdProviderKind.Google:
      return provider.google_service_account_key_set ?? false;
    case OpenIdProviderKind.Okta:
      return provider.okta_private_jwk_set ?? false;
    case OpenIdProviderKind.JumpCloud:
      return provider.jumpcloud_api_key_set ?? false;
    default:
      return provider.client_secret_set;
  }
};
