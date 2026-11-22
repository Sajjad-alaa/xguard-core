import type { AxiosError } from 'axios';
import { useRef, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import type { ApiError } from '../../../../shared/api/types';

export function useOAuthSubmit(onClose: () => void) {
  const [oauthError, setOauthError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handleCancel = () => {
    abortRef.current?.abort();
    onClose();
  };

  const beginOAuth = (): AbortSignal => {
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    return ctrl.signal;
  };

  const handleOAuthError = (err: unknown) => {
    if (err instanceof DOMException && err.name === 'AbortError') return;
    const apiMsg = (err as AxiosError<ApiError> | undefined)?.response?.data?.msg;
    setOauthError(
      apiMsg ?? (err instanceof Error ? err.message : m.settings_smtp_auth_oauth_error()),
    );
  };

  return { oauthError, setOauthError, handleCancel, beginOAuth, handleOAuthError };
}
