import { useMutation, useQuery } from '@tanstack/react-query';
import type { AxiosError } from 'axios';
import { useEffect, useState } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import type {
  ApiError,
  RadiusUsernameFormat,
  TestRadiusResponse,
} from '../../../shared/api/types';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { Checkbox } from '../../../shared/xguard-ui/components/Checkbox/Checkbox';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { InfoBanner } from '../../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import { Input } from '../../../shared/xguard-ui/components/Input/Input';
import { MarkedSection } from '../../../shared/xguard-ui/components/MarkedSection/MarkedSection';
import { MarkedSectionHeader } from '../../../shared/xguard-ui/components/MarkedSectionHeader/MarkedSectionHeader';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';

export const SettingsRadiusPage = () => {
  const { data: stored } = useQuery({
    queryKey: ['radius-settings'],
    queryFn: () => api.radius.getSettings().then((r) => r.data),
  });

  const [enabled, setEnabled] = useState(false);
  const [webLoginEnabled, setWebLoginEnabled] = useState(false);
  const [vpnMfaEnabled, setVpnMfaEnabled] = useState(true);
  const [primaryHost, setPrimaryHost] = useState('');
  const [primaryPort, setPrimaryPort] = useState('1812');
  const [primarySecret, setPrimarySecret] = useState('');
  const [secondaryHost, setSecondaryHost] = useState('');
  const [secondaryPort, setSecondaryPort] = useState('1812');
  const [secondarySecret, setSecondarySecret] = useState('');
  const [timeoutSecs, setTimeoutSecs] = useState('3');
  const [retries, setRetries] = useState('3');
  const [nasIdentifier, setNasIdentifier] = useState('xguard');
  const [nasIpAddress, setNasIpAddress] = useState('');
  const [usernameFormat, setUsernameFormat] = useState<RadiusUsernameFormat>('username');
  const [pushEnabled, setPushEnabled] = useState(false);
  const [pushPollIntervalSecs, setPushPollIntervalSecs] = useState('2');

  const [testUsername, setTestUsername] = useState('');
  const [testPassword, setTestPassword] = useState('');
  const [testResult, setTestResult] = useState<TestRadiusResponse | null>(null);

  useEffect(() => {
    if (!stored) return;
    setEnabled(stored.enabled);
    setWebLoginEnabled(stored.web_login_enabled);
    setVpnMfaEnabled(stored.vpn_mfa_enabled);
    setPrimaryHost(stored.primary_host);
    setPrimaryPort(String(stored.primary_port));
    setPrimarySecret('');
    setSecondaryHost(stored.secondary_host ?? '');
    setSecondaryPort(String(stored.secondary_port));
    setSecondarySecret('');
    setTimeoutSecs(String(stored.timeout_secs));
    setRetries(String(stored.retries));
    setNasIdentifier(stored.nas_identifier);
    setNasIpAddress(stored.nas_ip_address ?? '');
    setUsernameFormat(stored.username_format);
    setPushEnabled(stored.push_enabled);
    setPushPollIntervalSecs(String(stored.push_poll_interval_secs));
  }, [stored]);

  const { mutate: saveSettings, isPending: isSaving } = useMutation({
    mutationFn: api.radius.updateSettings,
    meta: { invalidate: [['radius-settings'], ['mfa-method-availability']] },
    onSuccess: () => {
      setPrimarySecret('');
      setSecondarySecret('');
      Snackbar.default(m.settings_radius_saved());
    },
    onError: (err: AxiosError<ApiError>) => {
      Snackbar.error(err.response?.data?.msg ?? m.settings_radius_save_failed());
    },
  });

  const { mutate: runTest, isPending: isTesting } = useMutation({
    mutationFn: api.radius.test,
    onSuccess: (res) => {
      setTestResult(res.data);
    },
    onError: (err: AxiosError<ApiError>) => {
      setTestResult(null);
      Snackbar.error(err.response?.data?.msg ?? m.settings_radius_test_failed());
    },
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    saveSettings({
      enabled,
      web_login_enabled: webLoginEnabled,
      vpn_mfa_enabled: vpnMfaEnabled,
      primary_host: primaryHost,
      primary_port: Number.parseInt(primaryPort, 10) || 1812,
      primary_secret: primarySecret || undefined,
      secondary_host: secondaryHost.trim() || null,
      secondary_port: Number.parseInt(secondaryPort, 10) || 1812,
      secondary_secret: secondarySecret || undefined,
      timeout_secs: Number.parseInt(timeoutSecs, 10) || 3,
      retries: Number.parseInt(retries, 10) || 3,
      nas_identifier: nasIdentifier,
      nas_ip_address: nasIpAddress.trim() || null,
      username_format: usernameFormat,
      push_enabled: pushEnabled,
      push_poll_interval_secs: Number.parseInt(pushPollIntervalSecs, 10) || 2,
    });
  };

  const handleTest = (e: React.FormEvent) => {
    e.preventDefault();
    runTest({
      username: testUsername,
      password: testPassword,
      primary_host: primaryHost || undefined,
      primary_port: Number.parseInt(primaryPort, 10) || 1812,
      primary_secret: primarySecret || undefined,
      secondary_host: secondaryHost.trim() || undefined,
      secondary_port: Number.parseInt(secondaryPort, 10) || 1812,
      secondary_secret: secondarySecret || undefined,
      timeout_secs: Number.parseInt(timeoutSecs, 10) || 3,
      retries: Number.parseInt(retries, 10) || 3,
      nas_identifier: nasIdentifier || undefined,
      nas_ip_address: nasIpAddress.trim() || undefined,
    });
  };

  return (
    <div id="settings-radius-page">
      <MarkedSection icon="settings">
        <MarkedSectionHeader
          title={m.settings_radius_title()}
          description={m.settings_radius_subtitle()}
        />
        <form onSubmit={handleSave}>
          <Checkbox
            text={m.settings_radius_enable()}
            active={enabled}
            onClick={() => setEnabled((v) => !v)}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Checkbox
            text={m.settings_radius_web_login()}
            active={webLoginEnabled}
            onClick={() => setWebLoginEnabled((v) => !v)}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Checkbox
            text={m.settings_radius_vpn_mfa()}
            active={vpnMfaEnabled}
            onClick={() => setVpnMfaEnabled((v) => !v)}
          />
          <Divider spacing={ThemeSpacing.Lg} />
          <Input
            label={m.settings_radius_primary_host()}
            value={primaryHost}
            onChange={(val) => setPrimaryHost(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="number"
            label={m.settings_radius_primary_port()}
            value={primaryPort}
            onChange={(val) => setPrimaryPort(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="password"
            label={m.settings_radius_primary_secret()}
            helper={
              stored?.primary_secret_set
                ? m.settings_radius_secret_configured()
                : m.settings_radius_secret_required()
            }
            value={primarySecret}
            onChange={(val) => setPrimarySecret(val == null ? '' : String(val))}
          />
          <Divider spacing={ThemeSpacing.Lg} />
          <Input
            label={m.settings_radius_secondary_host()}
            value={secondaryHost}
            onChange={(val) => setSecondaryHost(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="number"
            label={m.settings_radius_secondary_port()}
            value={secondaryPort}
            onChange={(val) => setSecondaryPort(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="password"
            label={m.settings_radius_secondary_secret()}
            helper={
              stored?.secondary_secret_set
                ? m.settings_radius_secret_configured()
                : m.settings_radius_secondary_secret_helper()
            }
            value={secondarySecret}
            onChange={(val) => setSecondarySecret(val == null ? '' : String(val))}
          />
          <Divider spacing={ThemeSpacing.Lg} />
          <Input
            label={m.settings_radius_nas_identifier()}
            value={nasIdentifier}
            onChange={(val) => setNasIdentifier(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            label={m.settings_radius_nas_ip()}
            value={nasIpAddress}
            onChange={(val) => setNasIpAddress(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="number"
            label={m.settings_radius_timeout()}
            value={timeoutSecs}
            onChange={(val) => setTimeoutSecs(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="number"
            label={m.settings_radius_retries()}
            value={retries}
            onChange={(val) => setRetries(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Md} />
          <Checkbox
            text={m.settings_radius_use_email_username()}
            active={usernameFormat === 'email'}
            onClick={() =>
              setUsernameFormat((f) => (f === 'email' ? 'username' : 'email'))
            }
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Checkbox
            text={m.settings_radius_push_enabled()}
            active={pushEnabled}
            onClick={() => setPushEnabled((v) => !v)}
          />
          {pushEnabled && (
            <>
              <SizedBox height={ThemeSpacing.Sm} />
              <Input
                type="number"
                label={m.settings_radius_push_interval()}
                value={pushPollIntervalSecs}
                onChange={(val) =>
                  setPushPollIntervalSecs(val == null ? '' : String(val))
                }
              />
            </>
          )}
          <SizedBox height={ThemeSpacing.Lg} />
          <Button
            type="submit"
            text={m.controls_save_changes()}
            loading={isSaving}
            data-testid="save-radius-settings"
          />
        </form>
      </MarkedSection>

      <SizedBox height={ThemeSpacing.Xl} />

      <MarkedSection icon="settings">
        <MarkedSectionHeader
          title={m.settings_radius_test_title()}
          description={m.settings_radius_test_description()}
        />
        {testResult && (
          <>
            <InfoBanner
              variant={testResult.decision === 'accept' ? 'info' : 'warning'}
              icon="info-outlined"
              text={`${testResult.decision.toUpperCase()}${testResult.reply_message ? `: ${testResult.reply_message}` : ''}`}
            />
            <SizedBox height={ThemeSpacing.Md} />
          </>
        )}
        <form onSubmit={handleTest}>
          <Input
            label={m.settings_radius_test_username()}
            value={testUsername}
            onChange={(val) => setTestUsername(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Sm} />
          <Input
            type="password"
            label={m.settings_radius_test_password()}
            value={testPassword}
            onChange={(val) => setTestPassword(val == null ? '' : String(val))}
          />
          <SizedBox height={ThemeSpacing.Md} />
          <Button
            type="submit"
            text={m.settings_radius_test_button()}
            loading={isTesting}
            data-testid="test-radius-settings"
          />
        </form>
      </MarkedSection>
    </div>
  );
};
