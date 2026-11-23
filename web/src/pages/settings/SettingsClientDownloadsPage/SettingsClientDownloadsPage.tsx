import { useMutation, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { AxiosError } from 'axios';
import { Suspense, useEffect, useMemo, useState } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import type { ApiError } from '../../../shared/api/types';
import {
  assetUrl,
  type ClientDownloadSettings,
  checkClientDownloadUrl,
  clientAssetNames,
} from '../../../shared/clientDownloads';
import { Breadcrumbs } from '../../../shared/components/Breadcrumbs/Breadcrumbs';
import { Page } from '../../../shared/components/Page/Page';
import { SettingsCard } from '../../../shared/components/SettingsCard/SettingsCard';
import { SettingsHeader } from '../../../shared/components/SettingsHeader/SettingsHeader';
import { SettingsLayout } from '../../../shared/components/SettingsLayout/SettingsLayout';
import { getClientDownloadSettingsQueryOptions } from '../../../shared/query';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { InfoBanner } from '../../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import { Input } from '../../../shared/xguard-ui/components/Input/Input';
import { InteractiveBlock } from '../../../shared/xguard-ui/components/InteractiveBlock/InteractiveBlock';
import { MarkedSection } from '../../../shared/xguard-ui/components/MarkedSection/MarkedSection';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import './style.scss';

const breadcrumbs = [
  <Link to="/settings" search={{ tab: 'general' }} key={0}>
    {m.settings_breadcrumb_general()}
  </Link>,
  <Link to="/settings/client-downloads" key={1}>
    {m.settings_client_downloads_title()}
  </Link>,
];

export const SettingsClientDownloadsPage = () => {
  return (
    <Page title={m.settings_page_title()}>
      <Breadcrumbs links={breadcrumbs} />
      <SettingsLayout>
        <SettingsHeader
          icon="download"
          title={m.settings_client_downloads_title()}
          subtitle={m.settings_client_downloads_subtitle()}
        />
        <Suspense fallback={<Skeleton height={480} />}>
          <Content />
        </Suspense>
      </SettingsLayout>
    </Page>
  );
};

type FieldErrors = Partial<
  Record<'base_url' | 'releases_url' | 'android_url' | 'ios_url', string>
>;

/** Client-side check mirroring Core's validation; Core checks again on save. */
export const validateClientDownloadForm = (
  form: ClientDownloadSettings,
): { errors: FieldErrors; insecure: boolean } => {
  const errors: FieldErrors = {};
  let insecure = false;
  const fields = [
    ['base_url', form.base_url, true, true],
    ['releases_url', form.releases_url, true, false],
    ['android_url', form.android_url ?? '', false, false],
    ['ios_url', form.ios_url ?? '', false, false],
  ] as const;
  for (const [name, value, required, pathOnly] of fields) {
    if (!value.trim()) {
      if (required) errors[name] = m.settings_client_downloads_invalid_url();
      continue;
    }
    const result = checkClientDownloadUrl(value, {
      allowHttp: form.allow_http,
      pathOnly,
    });
    if (!result.ok) {
      errors[name] = m.settings_client_downloads_invalid_url();
    } else if (result.insecure) {
      insecure = true;
    }
  }
  return { errors, insecure };
};

/** The editable fields only: the response also carries the asset names and defaults. */
const formValues = (stored: ClientDownloadSettings): ClientDownloadSettings => ({
  base_url: stored.base_url,
  releases_url: stored.releases_url,
  android_url: stored.android_url,
  ios_url: stored.ios_url,
  macos_installer: stored.macos_installer,
  allow_http: stored.allow_http,
});

const Content = () => {
  const { data: stored } = useSuspenseQuery(getClientDownloadSettingsQueryOptions);
  const [form, setForm] = useState<ClientDownloadSettings>(() => formValues(stored));

  useEffect(() => {
    setForm(formValues(stored));
  }, [stored]);

  const { errors, insecure } = useMemo(() => validateClientDownloadForm(form), [form]);
  const hasErrors = Object.keys(errors).length > 0;

  const { mutate: save, isPending } = useMutation({
    mutationFn: api.clientDownloads.update,
    meta: { invalidate: [['client_downloads'], ['activity-log']] },
    onSuccess: () => Snackbar.default(m.settings_client_downloads_saved()),
    onError: (err: AxiosError<ApiError>) => {
      Snackbar.error(
        err.response?.data?.msg ?? m.settings_client_downloads_save_failed(),
      );
    },
  });

  const setText =
    (key: 'base_url' | 'releases_url' | 'android_url' | 'ios_url') =>
    (value: string | number | null) =>
      setForm((current) => ({ ...current, [key]: value == null ? '' : String(value) }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (hasErrors) return;
    save({
      ...form,
      android_url: form.android_url?.trim() || null,
      ios_url: form.ios_url?.trim() || null,
    });
  };

  return (
    <SettingsCard id="settings-client-downloads-card">
      <form onSubmit={handleSubmit}>
        <MarkedSection icon="desktop">
          <h3>{m.settings_client_downloads_section_desktop()}</h3>
          <SizedBox height={ThemeSpacing.Md} />
          <Input
            label={m.settings_client_downloads_base_url()}
            helper={m.settings_client_downloads_base_url_helper({
              names: Object.values(clientAssetNames).join(', '),
            })}
            value={form.base_url}
            error={errors.base_url}
            onChange={setText('base_url')}
            testId="client-downloads-base-url"
          />
          {!errors.base_url && (
            <p
              className="client-downloads-example"
              data-testid="client-downloads-example"
            >
              {m.settings_client_downloads_example({
                url: assetUrl(form.base_url.trim(), clientAssetNames.windowsX64),
              })}
            </p>
          )}
          <SizedBox height={ThemeSpacing.Md} />
          <Input
            label={m.settings_client_downloads_releases_url()}
            helper={m.settings_client_downloads_releases_url_helper()}
            value={form.releases_url}
            error={errors.releases_url}
            onChange={setText('releases_url')}
            testId="client-downloads-releases-url"
          />
          <SizedBox height={ThemeSpacing.Md} />
          <InteractiveBlock
            variant="toggle"
            value={form.macos_installer}
            title={m.settings_client_downloads_macos_title()}
            content={m.settings_client_downloads_macos_content()}
            onClick={() =>
              setForm((current) => ({
                ...current,
                macos_installer: !current.macos_installer,
              }))
            }
          />
        </MarkedSection>
        <Divider spacing={ThemeSpacing.Xl2} />
        <MarkedSection icon="mobile">
          <h3>{m.settings_client_downloads_section_mobile()}</h3>
          <SizedBox height={ThemeSpacing.Md} />
          <Input
            label={m.settings_client_downloads_android_url()}
            helper={m.settings_client_downloads_mobile_helper()}
            value={form.android_url ?? ''}
            error={errors.android_url}
            onChange={setText('android_url')}
            testId="client-downloads-android-url"
          />
          <SizedBox height={ThemeSpacing.Md} />
          <Input
            label={m.settings_client_downloads_ios_url()}
            helper={m.settings_client_downloads_mobile_helper()}
            value={form.ios_url ?? ''}
            error={errors.ios_url}
            onChange={setText('ios_url')}
            testId="client-downloads-ios-url"
          />
        </MarkedSection>
        <Divider spacing={ThemeSpacing.Xl2} />
        <InteractiveBlock
          variant="toggle"
          value={form.allow_http}
          title={m.settings_client_downloads_allow_http_title()}
          content={m.settings_client_downloads_allow_http_content()}
          onClick={() =>
            setForm((current) => ({ ...current, allow_http: !current.allow_http }))
          }
        />
        {(insecure || form.allow_http) && (
          <>
            <SizedBox height={ThemeSpacing.Md} />
            <InfoBanner
              variant="warning"
              icon="warning-outlined"
              text={m.settings_client_downloads_http_warning()}
            />
          </>
        )}
        <SizedBox height={ThemeSpacing.Xl} />
        <div className="client-downloads-controls">
          <Button
            variant="secondary"
            text={m.settings_client_downloads_restore_defaults()}
            onClick={() =>
              setForm((current) => ({
                ...current,
                base_url: stored.defaults.base_url,
                releases_url: stored.defaults.releases_url,
                macos_installer: false,
                allow_http: false,
              }))
            }
          />
          <Button
            type="submit"
            text={m.controls_save_changes()}
            loading={isPending}
            disabled={hasErrors}
            testId="save-client-downloads"
          />
        </div>
      </form>
    </SettingsCard>
  );
};
