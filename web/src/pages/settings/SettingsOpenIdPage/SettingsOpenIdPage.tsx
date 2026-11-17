import { useStore } from '@tanstack/react-form';
import { useMutation, useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import './style.scss';
import axios from 'axios';
import { Suspense, useMemo, useState } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { type DirectorySyncReport, OpenIdProviderKind } from '../../../shared/api/types';
import { Breadcrumbs } from '../../../shared/components/Breadcrumbs/Breadcrumbs';
import { Controls } from '../../../shared/components/Controls/Controls';
import { Page } from '../../../shared/components/Page/Page';
import { SettingsCard } from '../../../shared/components/SettingsCard/SettingsCard';
import { SettingsHeader } from '../../../shared/components/SettingsHeader/SettingsHeader';
import { SettingsLayout } from '../../../shared/components/SettingsLayout/SettingsLayout';
import { useAppForm } from '../../../shared/form';
import { formChangeLogic } from '../../../shared/formLogic';
import { openModal } from '../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../shared/hooks/modalControls/modalTypes';
import { getSettingsQueryOptions } from '../../../shared/query';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { DirectorySyncSection } from './DirectorySyncSection';
import { needsConfirmation } from './dirsync';
import { formSchema, knownIssuers, supportsDirectorySync, toForm, toInput } from './form';
import { DirectorySyncDryRunModal } from './modals/DirectorySyncDryRunModal';

const breadcrumbs = [
  <Link key={0} to="/settings" search={{ tab: 'identity' }}>
    {m.settings_breadcrumb_identity_providers()}
  </Link>,
  <Link key={1} to="/settings/openid">
    {m.settings_openid_page_title()}
  </Link>,
];

const errorMessage = (error: unknown, fallback: string) =>
  axios.isAxiosError(error) && typeof error.response?.data?.msg === 'string'
    ? error.response.data.msg
    : fallback;

const kindOptions = Object.values(OpenIdProviderKind).map((kind) => ({
  key: kind,
  label: kind,
  value: kind,
}));

export const SettingsOpenIdPage = () => (
  <Page id="settings-openid-page" title={m.settings_page_title()}>
    <Breadcrumbs links={breadcrumbs} />
    <SettingsLayout>
      <SettingsHeader
        icon="globe"
        title={m.settings_openid_page_title()}
        subtitle={m.settings_openid_page_subtitle()}
      />
      <Suspense fallback={<Skeleton height={400} />}>
        <SettingsCard>
          <ProviderForm />
        </SettingsCard>
      </Suspense>
    </SettingsLayout>
  </Page>
);

const ProviderForm = () => {
  const { data: settings } = useSuspenseQuery(getSettingsQueryOptions);
  const { data: provider = null, isLoading } = useQuery({
    queryKey: ['openid', 'provider'],
    queryFn: api.openid.getProvider,
    select: (resp) => resp.data,
    retry: false,
  });
  const defaultValues = useMemo(
    () => toForm(provider, settings?.openid_create_account ?? false),
    [provider, settings],
  );

  const { mutateAsync: save } = useMutation({
    mutationFn: api.openid.setProvider,
    meta: { invalidate: [['openid'], ['settings']] },
  });
  const { mutate: test, isPending: testing } = useMutation({
    mutationFn: api.openid.testProvider,
    onSuccess: () => Snackbar.success(m.settings_openid_test_success()),
    onError: (error) =>
      Snackbar.error(errorMessage(error, m.settings_openid_test_failed())),
  });

  const [report, setReport] = useState<DirectorySyncReport | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const { data: syncStatus } = useQuery({
    queryKey: ['openid', 'provider', 'sync', 'status'],
    queryFn: api.openid.directorySyncStatus,
    select: (resp) => resp.data,
    enabled: provider?.directory_sync_enabled ?? false,
  });
  const showReport = (result: DirectorySyncReport) => {
    setReport(result);
    setReportOpen(true);
  };
  const { mutate: testDirectory, isPending: testingDirectory } = useMutation({
    mutationFn: api.openid.testDirectorySync,
    onSuccess: (res) =>
      Snackbar.success(
        m.settings_openid_sync_test_success({
          users: res.data.users,
          groups: res.data.groups,
        }),
      ),
    onError: (error) =>
      Snackbar.error(errorMessage(error, m.settings_openid_sync_test_failed())),
  });
  const { mutate: dryRun, isPending: dryRunning } = useMutation({
    mutationFn: api.openid.directorySyncDryRun,
    onSuccess: (res) => showReport(res.data),
    onError: (error) =>
      Snackbar.error(errorMessage(error, m.settings_openid_sync_test_failed())),
  });
  const syncInvalidate = [['openid'], ['user'], ['group']];
  const { mutate: syncNow, isPending: syncing } = useMutation({
    mutationFn: api.openid.directorySync,
    meta: { invalidate: syncInvalidate },
    onSuccess: (res) => {
      if (res.data.errors.length > 0) {
        Snackbar.error(m.settings_openid_sync_errors({ count: res.data.errors.length }));
      } else {
        Snackbar.default(m.settings_openid_sync_done());
      }
      showReport(res.data);
    },
    onError: (error) => {
      const message = errorMessage(error, m.settings_openid_sync_test_failed());
      // A run that disables or deletes many accounts must be confirmed.
      if (needsConfirmation(message)) {
        openModal(ModalName.ConfirmAction, {
          title: m.settings_openid_sync_confirm_title(),
          contentMd: message,
          actionPromise: () => api.openid.directorySync({ confirm_revocations: true }),
          invalidateKeys: syncInvalidate,
          submitProps: {
            text: m.settings_openid_sync_button_sync(),
            variant: 'critical',
          },
          onSuccess: () => Snackbar.default(m.settings_openid_sync_done()),
          onError: () => Snackbar.error(m.settings_openid_sync_test_failed()),
        });
        return;
      }
      Snackbar.error(message);
    },
  });

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: { onSubmit: formSchema, onChange: formSchema },
    onSubmit: async ({ value, formApi }) => {
      try {
        await save(toInput(value));
        if (value.create_accounts !== (settings?.openid_create_account ?? false)) {
          await api.settings.patchSettings({
            openid_create_account: value.create_accounts,
          });
        }
        Snackbar.success(m.settings_msg_saved());
        formApi.reset({
          ...value,
          client_secret: '',
          google_service_account_key: '',
          okta_private_jwk: '',
          jumpcloud_api_key: '',
        });
      } catch (error) {
        Snackbar.error(errorMessage(error, m.settings_msg_save_failed()));
      }
    },
  });
  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);
  const isPristine = useStore(form.store, (s) => s.isPristine || s.isDefaultValue);
  const kind = useStore(form.store, (s) => s.values.kind);
  const withValidForm = (action: (input: ReturnType<typeof toInput>) => void) => {
    const parsed = formSchema.safeParse(form.state.values);
    if (parsed.success) {
      action(toInput(parsed.data));
    } else {
      form.handleSubmit();
    }
  };

  if (isLoading) {
    return <Skeleton height={400} />;
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <form.AppField
          name="kind"
          listeners={{
            onChange: ({ value }) => {
              const issuer = knownIssuers[value];
              if (issuer && form.getFieldValue('issuer') === '') {
                form.setFieldValue('issuer', issuer);
              }
            },
          }}
        >
          {(field) => (
            <field.FormSelect
              required
              label={m.settings_openid_label_kind()}
              options={kindOptions}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="issuer">
          {(field) => (
            <field.FormInput
              required
              label={m.settings_openid_label_issuer()}
              helper={m.settings_openid_helper_issuer()}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="client_id">
          {(field) => (
            <field.FormInput
              required
              label={m.settings_openid_provider_label_client_id()}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="client_secret">
          {(field) => (
            <field.FormInput
              type="password"
              required={!provider?.client_secret_set}
              label={m.settings_openid_provider_label_client_secret()}
              helper={
                provider?.client_secret_set
                  ? m.settings_openid_helper_secret_kept()
                  : m.settings_openid_helper_redirect({
                      url: `${window.location.origin}/auth/callback`,
                    })
              }
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="display_name">
          {(field) => (
            <field.FormInput
              label={m.settings_openid_provider_label_display_name()}
              helper={m.settings_openid_helper_display_name()}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="create_accounts">
          {(field) => (
            <field.FormCheckbox text={m.settings_openid_label_create_accounts()} />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Md} />
        <form.AppField name="disable_password_management">
          {(field) => (
            <field.FormCheckbox
              text={m.settings_openid_label_disable_password_management()}
            />
          )}
        </form.AppField>
        <DirectorySyncSection form={form} provider={provider} />
        {supportsDirectorySync(kind) && (
          <>
            <SizedBox height={ThemeSpacing.Xl} />
            {syncStatus?.last_run && (
              <p className="directory-sync-status">
                {syncStatus.last_run.success
                  ? m.settings_openid_sync_last_run_ok({
                      time: new Date(`${syncStatus.last_run.finished}Z`).toLocaleString(),
                      changes: syncStatus.last_run.changes,
                    })
                  : m.settings_openid_sync_last_run_failed({
                      time: new Date(`${syncStatus.last_run.finished}Z`).toLocaleString(),
                      message: syncStatus.last_run.message ?? '',
                    })}
              </p>
            )}
            <div className="directory-sync-actions">
              <Button
                type="button"
                variant="outlined"
                text={m.settings_openid_sync_button_test()}
                testId="openid-sync-test"
                loading={testingDirectory}
                disabled={isSubmitting}
                onClick={() => withValidForm(testDirectory)}
              />
              <Button
                type="button"
                variant="outlined"
                text={m.settings_openid_sync_button_dry_run()}
                testId="openid-sync-dry-run"
                loading={dryRunning}
                disabled={isSubmitting}
                onClick={() => withValidForm(dryRun)}
              />
              {provider?.directory_sync_enabled && (
                <Button
                  type="button"
                  variant="outlined"
                  text={m.settings_openid_sync_button_sync()}
                  testId="openid-sync-now"
                  loading={syncing}
                  disabled={isSubmitting || !isPristine}
                  onClick={() => syncNow({})}
                />
              )}
            </div>
          </>
        )}
        <Controls>
          <form.AppField name="enabled">
            {(field) => <field.FormToggle label={m.settings_openid_label_enabled()} />}
          </form.AppField>
          <div className="right">
            {provider && (
              <Button
                type="button"
                variant="critical"
                text={m.controls_delete()}
                disabled={isSubmitting}
                onClick={() =>
                  openModal(ModalName.ConfirmAction, {
                    title: m.settings_openid_delete_title(),
                    contentMd: m.settings_openid_delete_body(),
                    actionPromise: () => api.openid.deleteProvider(),
                    invalidateKeys: [['openid']],
                    submitProps: { text: m.controls_delete(), variant: 'critical' },
                    onSuccess: () => {
                      Snackbar.default(m.settings_msg_saved());
                      form.reset(toForm(null, false));
                    },
                    onError: () => Snackbar.error(m.settings_msg_save_failed()),
                  })
                }
              />
            )}
            <Button
              type="button"
              variant="outlined"
              text={m.settings_openid_button_test()}
              loading={testing}
              disabled={isSubmitting}
              onClick={() => {
                const parsed = formSchema.safeParse(form.state.values);
                if (parsed.success) {
                  test(toInput(parsed.data));
                } else {
                  form.handleSubmit();
                }
              }}
            />
            <Button
              type="submit"
              text={m.controls_save_changes()}
              loading={isSubmitting}
            />
          </div>
        </Controls>
      </form.AppForm>
      <DirectorySyncDryRunModal
        isOpen={reportOpen}
        result={report}
        onClose={() => setReportOpen(false)}
      />
    </form>
  );
};
