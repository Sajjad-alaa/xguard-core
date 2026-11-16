import { describe, expect, it } from 'vitest';
import {
  formSchema,
  toForm,
  toInput,
} from '../src/pages/settings/SettingsOpenIdPage/form';

describe('OpenID provider form', () => {
  it('keeps the stored secret when the field is empty', () => {
    const form = toForm(
      {
        id: 1,
        kind: 'Google',
        issuer: 'https://accounts.google.com',
        client_id: 'id',
        enabled: true,
        display_name: null,
        disable_password_management: false,
        client_secret_set: true,
      },
      true,
    );
    expect(form.client_secret).toBe('');
    expect(form.create_accounts).toBe(true);
    expect(toInput(form).client_secret).toBeUndefined();
    expect(toInput({ ...form, client_secret: ' new ' }).client_secret).toBe('new');
    expect(toInput({ ...form, display_name: '  ' }).display_name).toBeNull();
  });

  it('validates the issuer and display name', () => {
    const base = toForm(null, false);
    expect(
      formSchema.safeParse({ ...base, issuer: 'https://idp.example.org', client_id: 'x' })
        .success,
    ).toBe(true);
    expect(
      formSchema.safeParse({ ...base, issuer: 'not a url', client_id: 'x' }).success,
    ).toBe(false);
    expect(
      formSchema.safeParse({
        ...base,
        issuer: 'https://idp.example.org',
        client_id: 'x',
        display_name: '<b>x</b>',
      }).success,
    ).toBe(false);
  });
});
