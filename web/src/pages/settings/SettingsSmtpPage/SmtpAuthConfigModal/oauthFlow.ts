import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import type {
  SmtpOAuthCallbackResponse,
  SmtpOAuthStartRequest,
} from '../../../../shared/api/types';

export const SMTP_OAUTH_CALLBACK_TYPE = 'smtp-oauth-callback';

export type OAuthCallbackPayload = {
  code?: string;
  state: string;
  error?: string;
};

type RawOAuthCallbackMessage = {
  type?: string;
  code?: string;
  state?: string;
  error?: string;
};

const closePopupQuietly = (popup: Window) => {
  try {
    popup.close();
  } catch {
    // detached after COOP
  }
};

const isSafeOAuthUrl = (rawUrl: string): boolean => {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === 'https:') return true;
    if (parsed.protocol !== 'http:') return false;
    const host = parsed.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  } catch {
    return false;
  }
};

export const waitForOAuthCallback = (
  popup: Window,
  signal?: AbortSignal,
  expectedState?: string,
): Promise<OAuthCallbackPayload> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) {
      closePopupQuietly(popup);
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }

    let broadcastChannel: BroadcastChannel | null = null;

    const cleanup = () => {
      window.removeEventListener('message', messageHandler);
      broadcastChannel?.close();
      clearTimeout(timeoutId);
      signal?.removeEventListener('abort', onAbort);
    };

    const handleResult = (data: RawOAuthCallbackMessage, fromPopup: boolean) => {
      if (data?.type !== SMTP_OAUTH_CALLBACK_TYPE) return;
      if (expectedState) {
        if (data.state && data.state !== expectedState) return;
        if (!data.state && !(data.error && fromPopup)) return;
      }
      cleanup();
      if (!data.state) {
        reject(new Error(data.error ?? m.settings_smtp_auth_oauth_error()));
        return;
      }
      resolve({
        code: data.code,
        state: data.state,
        error: data.error,
      });
    };

    const messageHandler = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      handleResult(event.data as RawOAuthCallbackMessage, event.source === popup);
    };

    window.addEventListener('message', messageHandler);

    // COOP fallback: BroadcastChannel is keyed by (origin, name), not by
    // browsing-context-group, so it crosses COOP boundaries without browser storage.
    try {
      broadcastChannel = new BroadcastChannel('smtp-oauth-relay');
      broadcastChannel.addEventListener('message', (event: MessageEvent) => {
        handleResult(event.data as RawOAuthCallbackMessage, false);
      });
    } catch {
      // BroadcastChannel unavailable; direct postMessage path still works without COOP.
    }

    const onAbort = () => {
      closePopupQuietly(popup);
      cleanup();
      reject(new DOMException('Aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort);

    // Timeout is the only "user abandoned" signal — popup.closed is unreliable after COOP.
    const timeoutId = setTimeout(
      () => {
        closePopupQuietly(popup);
        cleanup();
        reject(new Error(m.settings_smtp_auth_oauth_popup_closed()));
      },
      5 * 60 * 1000,
    );
  });

export const runSmtpOAuthFlow = async (
  request: SmtpOAuthStartRequest,
  signal?: AbortSignal,
): Promise<SmtpOAuthCallbackResponse> => {
  // Open the popup synchronously before awaiting /mail/oauth/start so browser popup blockers allow it.
  const popup = window.open(
    'about:blank',
    'smtp-oauth',
    'width=600,height=700,noopener=no',
  );
  if (!popup) {
    throw new Error(m.settings_smtp_auth_oauth_popup_blocked());
  }

  let authorizationUrl: string;
  try {
    const startResponse = await api.mail.oauthStart(request);
    authorizationUrl = startResponse.data.authorization_url;
  } catch (err) {
    closePopupQuietly(popup);
    throw err;
  }

  if (signal?.aborted) {
    closePopupQuietly(popup);
    throw new DOMException('Aborted', 'AbortError');
  }

  if (!isSafeOAuthUrl(authorizationUrl)) {
    closePopupQuietly(popup);
    throw new Error(m.settings_smtp_auth_oauth_error());
  }

  const expectedState = new URL(authorizationUrl).searchParams.get('state') ?? undefined;
  popup.location.href = authorizationUrl;

  const callback = await waitForOAuthCallback(popup, signal, expectedState);
  const callbackResponse = await api.mail.oauthCallback({
    state: callback.state,
    code: callback.code,
    error: callback.error,
  });
  return callbackResponse.data;
};
