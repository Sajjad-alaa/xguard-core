import './style.scss';
import { useMutation } from '@tanstack/react-query';
import type { AxiosError } from 'axios';
import { useEffect, useState } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import type {
  ApiError,
  MfaCompleteResponse,
  RadiusChallengeResponse,
} from '../../../shared/api/types';
import { LoginPage } from '../../../shared/components/LoginPage/LoginPage';
import { useAuth } from '../../../shared/hooks/useAuth';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { InfoBanner } from '../../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import { Input } from '../../../shared/xguard-ui/components/Input/Input';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSize, ThemeSpacing } from '../../../shared/xguard-ui/types';
import { isPresent } from '../../../shared/xguard-ui/utils/isPresent';
import { MfaLinks } from '../shared/MfaLinks/MfaLinks';

function isChallenge(
  data: MfaCompleteResponse | RadiusChallengeResponse,
): data is RadiusChallengeResponse {
  return 'status' in data && data.status === 'challenge';
}

export const LoginRadius = () => {
  const [code, setCode] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<RadiusChallengeResponse | null>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: api.auth.mfa.radius.verify,
    meta: {
      invalidate: [['me'], ['session-info']],
    },
    onSuccess: (response) => {
      setErrorMsg(null);
      if (response.status === 202 || isChallenge(response.data)) {
        const next = response.data as RadiusChallengeResponse;
        setChallenge(next);
        setCode('');
        return;
      }
      setChallenge(null);
      useAuth.getState().authSubject.next(response.data);
    },
    onError: (e: AxiosError<ApiError>) => {
      const respCode = e.response?.status;
      if (isPresent(respCode) && respCode < 500) {
        setErrorMsg(
          respCode === 429
            ? m.login_main_attempts_info()
            : (e.response?.data?.msg ?? m.form_error_code()),
        );
      } else {
        setErrorMsg(m.form_error_code());
      }
    },
  });

  useEffect(() => {
    if (!challenge?.push) return;
    const intervalMs = Math.max(1, challenge.poll_interval_secs) * 1000;
    const timer = window.setInterval(() => {
      mutate({ code: '', poll: true });
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [challenge?.push, challenge?.poll_interval_secs, mutate]);

  return (
    <LoginPage id="mfa-radius-page">
      <h1>{m.login_mfa_title()}</h1>
      <h2>{m.login_radius_subtitle()}</h2>
      <SizedBox height={ThemeSize.Xl5} />
      {challenge && (
        <>
          <InfoBanner
            variant="info"
            icon="info-outlined"
            text={
              challenge.message ||
              (challenge.push
                ? m.login_radius_push_waiting()
                : m.login_radius_challenge_prompt())
            }
          />
          {challenge.push && (
            <>
              <SizedBox height={ThemeSpacing.Sm} />
              <div className="radius-push-status" role="status" aria-live="polite">
                <span className="pulse-dot" aria-hidden="true" />
                <span>{m.login_radius_polling_active()}</span>
              </div>
            </>
          )}
          <SizedBox height={ThemeSpacing.Md} />
        </>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setErrorMsg(null);
          mutate({ code });
        }}
      >
        <Input
          size="lg"
          type="text"
          label={m.form_label_auth_code()}
          helper={m.login_radius_code_helper()}
          value={code}
          error={errorMsg ?? undefined}
          onChange={(val) => setCode(val == null ? '' : String(val))}
        />
        <SizedBox height={ThemeSpacing.Lg} />
        <div className="radius-actions">
          <Button
            type="submit"
            size="big"
            loading={isPending}
            text={m.controls_submit()}
            data-testid="submit-radius"
          />
          {!challenge?.push && (
            <Button
              type="button"
              variant="outlined"
              size="big"
              disabled={isPending}
              text={m.login_radius_send_challenge()}
              data-testid="trigger-radius-challenge"
              onClick={() => {
                setErrorMsg(null);
                mutate({ code: '' });
              }}
            />
          )}
        </div>
      </form>
      <MfaLinks />
    </LoginPage>
  );
};
