import { useStore } from '@tanstack/react-form';
import { m } from '../../../paraglide/messages';
import {
  DirectorySyncBehavior,
  DirectorySyncTarget,
  type ExternalOpenIdProvider,
  OpenIdProviderKind,
} from '../../../shared/api/types';
import { DescriptionBlock } from '../../../shared/components/DescriptionBlock/DescriptionBlock';
import { withForm } from '../../../shared/form';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { EvenSplit } from '../../../shared/xguard-ui/components/EvenSplit/EvenSplit';
import { Fold } from '../../../shared/xguard-ui/components/Fold/Fold';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { directorySecretStored, supportsDirectorySync, toForm } from './form';

const targetOptions = [
  { key: DirectorySyncTarget.All, label: m.cmp_sync_behavior_target_all() },
  { key: DirectorySyncTarget.Users, label: m.cmp_sync_behavior_target_users() },
  { key: DirectorySyncTarget.Groups, label: m.cmp_sync_behavior_target_groups() },
].map((option) => ({ ...option, value: option.key }));

const behaviorOptions = [
  { key: DirectorySyncBehavior.Keep, label: m.settings_openid_sync_behavior_keep() },
  {
    key: DirectorySyncBehavior.Disable,
    label: m.settings_openid_sync_behavior_disable(),
  },
  { key: DirectorySyncBehavior.Delete, label: m.settings_openid_sync_behavior_delete() },
].map((option) => ({ ...option, value: option.key }));

/** The directory sync settings for the provider kind picked in the form. */
export const DirectorySyncSection = withForm({
  defaultValues: toForm(null, false),
  props: { provider: null as ExternalOpenIdProvider | null },
  render: function Render({ form, provider }) {
    const kind = useStore(form.store, (s) => s.values.kind);
    const enabled = useStore(form.store, (s) => s.values.directory_sync_enabled);
    const secretStored = directorySecretStored(provider, kind);

    if (!supportsDirectorySync(kind)) {
      return (
        <>
          <Divider spacing={ThemeSpacing.Xl} />
          <DescriptionBlock title={m.settings_openid_provider_directory_sync_title()}>
            <p>{m.settings_openid_sync_unsupported()}</p>
          </DescriptionBlock>
        </>
      );
    }

    return (
      <>
        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.settings_openid_provider_directory_sync_title()}>
          <p>{m.settings_openid_sync_description()}</p>
        </DescriptionBlock>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="directory_sync_enabled">
          {(field) => (
            <field.FormToggle
              label={m.settings_openid_provider_directory_sync_toggle()}
            />
          )}
        </form.AppField>
        <Fold open={enabled}>
          <SizedBox height={ThemeSpacing.Xl} />
          {kind === OpenIdProviderKind.Google && (
            <>
              <DescriptionBlock title={m.settings_openid_sync_google_title()}>
                <p>{m.settings_openid_sync_google_help()}</p>
              </DescriptionBlock>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="admin_email">
                {(field) => (
                  <field.FormInput
                    required
                    label={m.settings_openid_provider_label_admin_email()}
                    helper={m.settings_openid_sync_helper_admin_email()}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="google_service_account_key">
                {(field) => (
                  <field.FormTextarea
                    required={!secretStored}
                    label={m.settings_openid_provider_google_service_account_key_title()}
                    helper={
                      secretStored
                        ? m.settings_openid_sync_helper_key_kept({
                            account: provider?.google_service_account_email ?? '',
                          })
                        : m.settings_openid_sync_helper_google_key()
                    }
                    minHeight={80}
                  />
                )}
              </form.AppField>
            </>
          )}
          {kind === OpenIdProviderKind.Microsoft && (
            <DescriptionBlock title={m.settings_openid_sync_microsoft_title()}>
              <p>{m.settings_openid_sync_microsoft_help()}</p>
            </DescriptionBlock>
          )}
          {kind === OpenIdProviderKind.Okta && (
            <>
              <DescriptionBlock title={m.settings_openid_sync_okta_title()}>
                <p>{m.settings_openid_sync_okta_help()}</p>
              </DescriptionBlock>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="okta_dirsync_client_id">
                {(field) => (
                  <field.FormInput
                    required
                    label={m.settings_openid_provider_label_okta_directory_sync_client_id()}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="okta_private_jwk">
                {(field) => (
                  <field.FormTextarea
                    required={!secretStored}
                    label={m.settings_openid_provider_label_okta_directory_sync_client_private_key()}
                    helper={
                      secretStored
                        ? m.settings_openid_provider_helper_okta_directory_sync_client_private_key()
                        : m.settings_openid_sync_helper_okta_key()
                    }
                    minHeight={80}
                  />
                )}
              </form.AppField>
            </>
          )}
          {kind === OpenIdProviderKind.JumpCloud && (
            <>
              <DescriptionBlock title={m.settings_openid_sync_jumpcloud_title()}>
                <p>{m.settings_openid_sync_jumpcloud_help()}</p>
              </DescriptionBlock>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="jumpcloud_api_key">
                {(field) => (
                  <field.FormInput
                    type="password"
                    required={!secretStored}
                    label={m.settings_openid_provider_label_jumpcloud_api_key()}
                    helper={
                      secretStored ? m.settings_openid_helper_secret_kept() : undefined
                    }
                  />
                )}
              </form.AppField>
            </>
          )}
          <SizedBox height={ThemeSpacing.Xl} />
          <EvenSplit>
            <form.AppField name="directory_sync_target">
              {(field) => (
                <field.FormSelect
                  required
                  options={targetOptions}
                  label={m.settings_openid_provider_label_sync_target()}
                  helper={m.settings_openid_sync_helper_target()}
                />
              )}
            </form.AppField>
            <form.AppField name="directory_sync_interval">
              {(field) => (
                <field.FormInput
                  notNull
                  required
                  type="number"
                  label={m.settings_openid_provider_label_sync_interval()}
                  helper={m.settings_openid_sync_helper_interval()}
                />
              )}
            </form.AppField>
          </EvenSplit>
          <SizedBox height={ThemeSpacing.Xl} />
          <EvenSplit>
            <form.AppField name="directory_sync_user_behavior">
              {(field) => (
                <field.FormSelect
                  required
                  options={behaviorOptions}
                  label={m.settings_openid_provider_label_sync_user_behavior()}
                  helper={m.settings_openid_sync_helper_user_behavior()}
                />
              )}
            </form.AppField>
            <form.AppField name="directory_sync_admin_behavior">
              {(field) => (
                <field.FormSelect
                  required
                  options={behaviorOptions}
                  label={m.settings_openid_provider_label_sync_admin_behavior()}
                  helper={m.settings_openid_sync_helper_admin_behavior()}
                />
              )}
            </form.AppField>
          </EvenSplit>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="directory_sync_group_match">
            {(field) => (
              <field.FormInput
                label={m.settings_openid_provider_label_sync_only_matching_groups()}
                helper={m.settings_openid_sync_helper_group_match()}
              />
            )}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="directory_sync_user_groups">
            {(field) => (
              <field.FormInput
                label={m.settings_openid_provider_label_sync_users_from_groups()}
                helper={m.settings_openid_sync_helper_user_groups()}
              />
            )}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="prefetch_users">
            {(field) => <field.FormCheckbox text={m.settings_openid_sync_prefetch()} />}
          </form.AppField>
        </Fold>
      </>
    );
  },
});
