import z from 'zod';
import { m } from '../../../paraglide/messages';
import {
  type ExternalOpenIdProvider,
  type ExternalOpenIdProviderInput,
  OpenIdProviderKind,
  type OpenIdProviderKindValue,
} from '../../../shared/api/types';
import { nameValidator } from '../../../shared/validators';

/** Well-known issuers, filled in when a provider kind is picked. */
export const knownIssuers: Partial<Record<OpenIdProviderKindValue, string>> = {
  Google: 'https://accounts.google.com',
};

export const formSchema = z.object({
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
});

/** An empty secret field keeps the stored secret. */
export const toInput = (value: FormFields): ExternalOpenIdProviderInput => ({
  kind: value.kind,
  issuer: value.issuer.trim(),
  client_id: value.client_id.trim(),
  client_secret:
    value.client_secret.trim() === '' ? undefined : value.client_secret.trim(),
  enabled: value.enabled,
  display_name: value.display_name.trim() === '' ? null : value.display_name.trim(),
  disable_password_management: value.disable_password_management,
});
