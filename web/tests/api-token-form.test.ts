import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { describe, expect, it } from 'vitest';
import {
  addTokenSchema,
  EXPIRY_NEVER,
  isExpired,
  toAddRequest,
  tokenNameSchema,
} from '../src/pages/user-profile/UserProfilePage/tabs/ProfileApiTokensTab/apiTokens';
import type { ApiToken } from '../src/shared/api/types';

dayjs.extend(utc);

const token = (expires_at: string | null): ApiToken => ({
  id: 1,
  user_id: 1,
  name: 'ci',
  hint: 'xgt_AbCd',
  created_at: '2026-01-01T00:00:00',
  expires_at,
  last_used_at: null,
  last_used_ip: null,
  read_only: false,
});

describe('API token form', () => {
  it('accepts names the server accepts', () => {
    expect(tokenNameSchema.safeParse('Deploy bot (prod)').success).toBe(true);
    expect(tokenNameSchema.safeParse('x'.repeat(64)).success).toBe(true);
  });

  it('refuses empty, long or unsafe names', () => {
    for (const bad of ['', '   ', 'x'.repeat(65), '<b>x</b>', '[x](y)']) {
      expect(tokenNameSchema.safeParse(bad).success, bad).toBe(false);
    }
  });

  it('builds the request', () => {
    const fields = addTokenSchema.parse({ name: ' ci ', expiry: '30', read_only: true });
    expect(toAddRequest('admin', fields)).toEqual({
      username: 'admin',
      name: 'ci',
      expires_in_days: 30,
      read_only: true,
    });
    expect(
      toAddRequest('admin', { name: 'ci', expiry: EXPIRY_NEVER, read_only: false })
        .expires_in_days,
    ).toBeNull();
  });

  it('knows when a token has expired', () => {
    const now = dayjs.utc('2026-06-01T12:00:00');
    expect(isExpired(token(null), now)).toBe(false);
    expect(isExpired(token('2026-06-01T12:00:01'), now)).toBe(false);
    expect(isExpired(token('2026-06-01T12:00:00'), now)).toBe(true);
    expect(isExpired(token('2026-01-01T00:00:00'), now)).toBe(true);
  });
});
