import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  runSmtpOAuthFlow,
  SMTP_OAUTH_CALLBACK_TYPE,
  waitForOAuthCallback,
} from '../src/pages/settings/SettingsSmtpPage/SmtpAuthConfigModal/oauthFlow';
import api from '../src/shared/api/api';

describe('SMTP XOAUTH2 popup flow', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('resolves code and state from same-origin postMessage', async () => {
    const popup = { close: vi.fn() } as unknown as Window;
    const promise = waitForOAuthCallback(popup);

    // Other-origin message is ignored.
    window.dispatchEvent(
      new MessageEvent('message', {
        origin: 'https://evil.example',
        data: { type: SMTP_OAUTH_CALLBACK_TYPE, code: 'bad', state: 'bad' },
      }),
    );

    // Valid same-origin callback resolves.
    window.dispatchEvent(
      new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: SMTP_OAUTH_CALLBACK_TYPE,
          code: 'auth-code-1',
          state: 'state-1',
        },
      }),
    );

    await expect(promise).resolves.toEqual({
      code: 'auth-code-1',
      state: 'state-1',
      error: undefined,
    });
  });

  it('resolves via BroadcastChannel when COOP severs window.opener', async () => {
    const channels: Array<{
      listeners: Array<(event: MessageEvent) => void>;
      closed: boolean;
    }> = [];
    class MockBroadcastChannel {
      listeners: Array<(event: MessageEvent) => void> = [];
      closed = false;
      constructor(public name: string) {
        channels.push(this);
      }
      addEventListener(type: string, cb: (event: MessageEvent) => void) {
        if (type === 'message') this.listeners.push(cb);
      }
      close() {
        this.closed = true;
      }
    }
    vi.stubGlobal('BroadcastChannel', MockBroadcastChannel);

    const popup = { close: vi.fn() } as unknown as Window;
    const promise = waitForOAuthCallback(popup);
    expect(channels).toHaveLength(1);
    expect(channels[0].name).toBe('smtp-oauth-relay');

    for (const cb of channels[0].listeners) {
      cb(
        new MessageEvent('message', {
          data: {
            type: SMTP_OAUTH_CALLBACK_TYPE,
            code: 'coop-code',
            state: 'coop-state',
          },
        }),
      );
    }

    await expect(promise).resolves.toEqual({
      code: 'coop-code',
      state: 'coop-state',
      error: undefined,
    });
    expect(channels[0].closed).toBe(true);
  });

  it('rejects when callback payload omits state', async () => {
    const popup = { close: vi.fn() } as unknown as Window;
    const promise = waitForOAuthCallback(popup);

    window.dispatchEvent(
      new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: SMTP_OAUTH_CALLBACK_TYPE,
          code: 'auth-code',
          error: 'Missing state parameter',
        },
      }),
    );

    await expect(promise).rejects.toThrow('Missing state parameter');
  });

  it('closes the popup and rejects with AbortError when aborted', async () => {
    const close = vi.fn();
    const popup = { close } as unknown as Window;
    const controller = new AbortController();
    const promise = waitForOAuthCallback(popup, controller.signal);

    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
    expect(close).toHaveBeenCalledTimes(1);
  });

  describe('runSmtpOAuthFlow', () => {
    beforeEach(() => {
      vi.restoreAllMocks();
    });

    it('throws when popup is blocked', async () => {
      vi.spyOn(window, 'open').mockReturnValue(null);
      await expect(
        runSmtpOAuthFlow({
          provider: 'google',
          client_id: 'cid',
          client_secret: 'secret',
          sender: 'mailer@example.org',
          tls_verify_cert: true,
        }),
      ).rejects.toThrow(/popup/i);
    });

    it('opens popup before calling oauthStart, navigates, and relays callback to oauthCallback', async () => {
      const calls: string[] = [];
      const popup = {
        close: vi.fn(),
        location: {
          set href(url: string) {
            calls.push(`navigate:${url}`);
          },
        },
      } as unknown as Window;

      vi.spyOn(window, 'open').mockImplementation(() => {
        calls.push('open');
        return popup;
      });
      const startSpy = vi.spyOn(api.mail, 'oauthStart').mockImplementation(async () => {
        calls.push('start');
        return {
          data: {
            authorization_url:
              'https://accounts.google.com/o/oauth2/v2/auth?state=srv-state',
          },
        } as never;
      });
      const callbackSpy = vi.spyOn(api.mail, 'oauthCallback').mockResolvedValue({
        data: { provider: 'google', sender: 'mailer@example.org' },
      } as never);

      const flowPromise = runSmtpOAuthFlow({
        provider: 'google',
        client_id: 'cid',
        client_secret: 'secret',
        sender: 'mailer@example.org',
        tls_verify_cert: true,
      });

      // Wait a microtask tick for oauthStart to settle and navigate the popup.
      await new Promise((r) => setTimeout(r, 0));
      window.dispatchEvent(
        new MessageEvent('message', {
          origin: window.location.origin,
          data: {
            type: SMTP_OAUTH_CALLBACK_TYPE,
            code: 'srv-code',
            state: 'srv-state',
          },
        }),
      );

      const result = await flowPromise;
      expect(result).toEqual({ provider: 'google', sender: 'mailer@example.org' });
      expect(calls).toEqual([
        'open',
        'start',
        'navigate:https://accounts.google.com/o/oauth2/v2/auth?state=srv-state',
      ]);
      expect(startSpy).toHaveBeenCalledTimes(1);
      expect(callbackSpy).toHaveBeenCalledWith({
        state: 'srv-state',
        code: 'srv-code',
        error: undefined,
      });
    });

    it('closes popup if oauthStart fails', async () => {
      const close = vi.fn();
      const popup = {
        close,
        location: { href: '' },
      } as unknown as Window;
      vi.spyOn(window, 'open').mockReturnValue(popup);
      vi.spyOn(api.mail, 'oauthStart').mockRejectedValue(new Error('bad client secret'));

      await expect(
        runSmtpOAuthFlow({
          provider: 'microsoft',
          client_id: 'cid',
          sender: 'mailer@example.org',
          tls_verify_cert: true,
        }),
      ).rejects.toThrow('bad client secret');
      expect(close).toHaveBeenCalledTimes(1);
    });

    it('ignores mismatched callback state messages and waits for matching state', async () => {
      const popup = { close: vi.fn() } as unknown as Window;
      const promise = waitForOAuthCallback(popup, undefined, 'expected-state');

      window.dispatchEvent(
        new MessageEvent('message', {
          origin: window.location.origin,
          data: {
            type: SMTP_OAUTH_CALLBACK_TYPE,
            code: 'wrong-code',
            state: 'stale-state',
          },
        }),
      );

      window.dispatchEvent(
        new MessageEvent('message', {
          origin: window.location.origin,
          data: {
            type: SMTP_OAUTH_CALLBACK_TYPE,
            code: 'good-code',
            state: 'expected-state',
          },
        }),
      );

      await expect(promise).resolves.toEqual({
        code: 'good-code',
        state: 'expected-state',
        error: undefined,
      });
    });

    it('closes popup without navigating when aborted during oauthStart', async () => {
      const close = vi.fn();
      const setHref = vi.fn();
      const popup = {
        close,
        location: {
          set href(url: string) {
            setHref(url);
          },
        },
      } as unknown as Window;
      vi.spyOn(window, 'open').mockReturnValue(popup);
      const controller = new AbortController();
      vi.spyOn(api.mail, 'oauthStart').mockImplementation(async () => {
        controller.abort();
        return {
          data: {
            authorization_url:
              'https://accounts.google.com/o/oauth2/v2/auth?state=srv-state',
          },
        } as never;
      });

      await expect(
        runSmtpOAuthFlow(
          {
            provider: 'google',
            client_id: 'cid',
            client_secret: 'secret',
            sender: 'mailer@example.org',
            tls_verify_cert: true,
          },
          controller.signal,
        ),
      ).rejects.toMatchObject({ name: 'AbortError' });
      expect(close).toHaveBeenCalledTimes(1);
      expect(setHref).not.toHaveBeenCalled();
    });
  });
});
