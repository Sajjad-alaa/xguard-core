import { useStore } from '@tanstack/react-form';
import { useMutation, useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import axios from 'axios';
import { Suspense, useMemo } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { OpenIdProviderKind } from '../../../shared/api/types';
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
import { formSchema, knownIssuers, toForm, toInput } from './form';

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
        formApi.reset({ ...value, client_secret: '' });
      } catch (error) {
        Snackbar.error(errorMessage(error, m.settings_msg_save_failed()));
      }
    },
  });
  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);

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
    </form>
  );
};
