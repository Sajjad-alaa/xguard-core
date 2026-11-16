import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import z from 'zod';
import { m } from '../../../../../paraglide/messages';
import type { AddApiTokenRequest, ApiToken } from '../../../../../shared/api/types';
import { nameValidator } from '../../../../../shared/validators';

dayjs.extend(utc);

/** Matches the server's limit. */
export const MAX_TOKEN_NAME_LENGTH = 64;

export const tokenNameSchema = z
  .string()
  .trim()
  .min(1, m.form_error_required())
  .max(MAX_TOKEN_NAME_LENGTH, m.modal_api_token_name_too_long())
  .pipe(nameValidator);

export const EXPIRY_NEVER = 'never';
export const DEFAULT_EXPIRY = '90';

export const expiryOptions = () =>
  [
    { key: '30', label: m.modal_add_api_token_expiry_days({ days: 30 }), value: '30' },
    { key: '90', label: m.modal_add_api_token_expiry_days({ days: 90 }), value: '90' },
    { key: '365', label: m.modal_add_api_token_expiry_year(), value: '365' },
    {
      key: EXPIRY_NEVER,
      label: m.modal_add_api_token_expiry_never(),
      value: EXPIRY_NEVER,
    },
  ] as const;

export const addTokenSchema = z.object({
  name: tokenNameSchema,
  expiry: z.string(),
  read_only: z.boolean(),
});

export type AddTokenFields = z.infer<typeof addTokenSchema>;

export const toAddRequest = (
  username: string,
  { name, expiry, read_only }: AddTokenFields,
): AddApiTokenRequest => ({
  username,
  name: name.trim(),
  expires_in_days: expiry === EXPIRY_NEVER ? null : Number(expiry),
  read_only,
});

/** Server timestamps are UTC without a zone suffix. */
export const isExpired = (token: ApiToken, now = dayjs()) =>
  token.expires_at !== null && !dayjs.utc(token.expires_at).isAfter(now);
