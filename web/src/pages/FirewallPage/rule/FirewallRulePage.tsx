import './style.scss';
import { useStore } from '@tanstack/react-form';
import { useMutation, useSuspenseQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import axios from 'axios';
import { useMemo } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { type FirewallRule, FirewallRuleAction } from '../../../shared/api/types';
import { EditPage } from '../../../shared/components/EditPage/EditPage';
import { EditPageControls } from '../../../shared/components/EditPageControls/EditPageControls';
import { EditPageFormSection } from '../../../shared/components/EditPageFormSection/EditPageFormSection';
import { useAppForm } from '../../../shared/form';
import { formChangeLogic } from '../../../shared/formLogic';
import { openModal } from '../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../shared/hooks/modalControls/modalTypes';
import { getFirewallRulesQueryOptions } from '../../../shared/query';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { EmptyStateFlexible } from '../../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { actionLabel, protocolName } from '../summary';
import { type FirewallNames, useFirewallNames } from '../useFirewallNames';
import {
  COMMON_PROTOCOLS,
  duplicateRuleToForm,
  emptyForm,
  type FormFields,
  formSchema,
  formToInput,
  ruleToForm,
} from './form';

type Props = {
  ruleId?: number;
  duplicateOf?: number;
};

const actionOptions = [
  FirewallRuleAction.Allow,
  FirewallRuleAction.Deny,
  FirewallRuleAction.Reject,
].map((action) => ({ key: action, label: actionLabel(action), value: action }));

const toOptions = (items: FirewallNames['users']) =>
  items.map((item) => ({ id: item.id, label: item.label }));

const errorMessage = (error: unknown) =>
  axios.isAxiosError(error) && typeof error.response?.data?.msg === 'string'
    ? error.response.data.msg
    : m.firewall_save_failed();

export const FirewallRulePage = ({ ruleId, duplicateOf }: Props) => {
  const navigate = useNavigate();
  const { data: rules } = useSuspenseQuery(getFirewallRulesQueryOptions);
  const names = useFirewallNames();

  const existingRule = useMemo(
    () => (ruleId !== undefined ? rules.find((r) => r.id === ruleId) : undefined),
    [rules, ruleId],
  );
  const sourceRule = useMemo(
    () =>
      duplicateOf !== undefined ? rules.find((r) => r.id === duplicateOf) : undefined,
    [rules, duplicateOf],
  );

  const isEdit = ruleId !== undefined;

  if (isEdit && !existingRule) {
    return (
      <EditPage
        pageTitle={m.firewall_title()}
        links={[
          <Link key="firewall" to="/firewall">
            {m.firewall_title()}
          </Link>,
        ]}
        onBack={() => navigate({ to: '/firewall' })}
        headerProps={{ title: m.firewall_modal_edit_title() }}
      >
        <EmptyStateFlexible
          icon="rules"
          title={m.firewall_rule_not_found_title()}
          subtitle={m.firewall_rule_not_found_subtitle()}
          primaryAction={{
            text: m.firewall_back_to_rules(),
            onClick: () => navigate({ to: '/firewall' }),
          }}
        />
      </EditPage>
    );
  }

  const breadcrumbs = [
    <Link key="firewall" to="/firewall">
      {m.firewall_title()}
    </Link>,
    <span key="current">
      {existingRule ? existingRule.name : m.firewall_modal_create_title()}
    </span>,
  ];

  return (
    <EditPage
      id="firewall-rule-page"
      pageTitle={m.firewall_title()}
      links={breadcrumbs}
      onBack={() => navigate({ to: '/firewall' })}
      headerProps={{
        title: existingRule
          ? m.firewall_modal_edit_title()
          : m.firewall_modal_create_title(),
      }}
    >
      <FirewallRuleForm rule={existingRule} duplicateSource={sourceRule} names={names} />
    </EditPage>
  );
};

type FormProps = {
  rule?: FirewallRule;
  duplicateSource?: FirewallRule;
  names: FirewallNames;
};

const FirewallRuleForm = ({ rule, duplicateSource, names }: FormProps) => {
  const navigate = useNavigate();

  const defaultValues = useMemo((): FormFields => {
    if (rule) return ruleToForm(rule);
    if (duplicateSource) return duplicateRuleToForm(duplicateSource);
    return emptyForm();
  }, [rule, duplicateSource]);

  const mutationOptions = {
    meta: { invalidate: [['firewall']] },
    onSuccess: () => {
      Snackbar.success(m.firewall_save_success());
      navigate({ to: '/firewall' });
    },
    onError: (error: unknown) => Snackbar.error(errorMessage(error)),
  };

  const { mutateAsync: addRule } = useMutation({
    mutationFn: api.firewall.addRule,
    ...mutationOptions,
  });
  const { mutateAsync: editRule } = useMutation({
    mutationFn: api.firewall.editRule,
    ...mutationOptions,
  });

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: {
      onSubmit: formSchema,
      onChange: formSchema,
    },
    onSubmit: async ({ value }) => {
      const input = formToInput(value, rule?.expires_at ?? null);
      try {
        if (rule) {
          await editRule({ id: rule.id, ...input });
        } else {
          await addRule(input);
        }
      } catch {
        // Reported by the mutation's onError.
      }
    },
  });

  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);
  const anySource = useStore(form.store, (s) => s.values.any_source);
  const allUsers = useStore(form.store, (s) => s.values.all_users);
  const allDevices = useStore(form.store, (s) => s.values.all_network_devices);
  const anyDestination = useStore(form.store, (s) => s.values.any_destination);
  const allLocations = useStore(form.store, (s) => s.values.all_locations);

  const userOptions = useMemo(() => toOptions(names.users), [names.users]);
  const groupOptions = useMemo(() => toOptions(names.groups), [names.groups]);
  const deviceOptions = useMemo(() => toOptions(names.devices), [names.devices]);
  const locationOptions = useMemo(() => toOptions(names.locations), [names.locations]);
  const counter = (count: number) => `+${count}`;

  return (
    <form
      className="firewall-rule-form"
      onSubmit={(e) => {
        e.stopPropagation();
        e.preventDefault();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <EditPageFormSection label={m.firewall_section_general()}>
          <form.AppField name="name">
            {(field) => <field.FormInput required label={m.firewall_label_name()} />}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="description">
            {(field) => <field.FormTextarea label={m.firewall_label_description()} />}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <div className="row">
            <form.AppField name="action">
              {(field) => (
                <field.FormSelect
                  required
                  label={m.firewall_label_action()}
                  helper={m.firewall_helper_action()}
                  options={actionOptions}
                />
              )}
            </form.AppField>
            <form.AppField name="priority">
              {(field) => (
                <field.FormInput
                  type="number"
                  required
                  label={m.firewall_label_priority()}
                  helper={m.firewall_helper_priority()}
                />
              )}
            </form.AppField>
          </div>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="enabled">
            {(field) => <field.FormToggle label={m.firewall_label_enabled()} />}
          </form.AppField>
        </EditPageFormSection>

        <Divider spacing={ThemeSpacing.Xl2} />

        <EditPageFormSection label={m.firewall_section_sources()}>
          <p className="section-helper">{m.firewall_section_sources_text()}</p>
          <form.AppField name="any_source">
            {(field) => <field.FormToggle label={m.firewall_label_any_source()} />}
          </form.AppField>
          {!anySource && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="users">
                {(field) => (
                  <field.FormSelectMultiple
                    options={userOptions}
                    counterText={counter}
                    editText={m.firewall_edit_selection()}
                    modalTitle={m.firewall_select_users()}
                    toggleText={m.firewall_all_users()}
                    toggleValue={allUsers}
                    onToggleChange={(value) => form.setFieldValue('all_users', value)}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <p className="field-label">{m.firewall_label_groups()}</p>
              <form.AppField name="groups">
                {(field) => (
                  <field.FormSelectMultiple
                    options={groupOptions}
                    counterText={counter}
                    editText={m.firewall_edit_selection()}
                    modalTitle={m.firewall_select_groups()}
                    toggleValue={false}
                    onToggleChange={() => {}}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="devices">
                {(field) => (
                  <field.FormSelectMultiple
                    options={deviceOptions}
                    counterText={counter}
                    editText={m.firewall_edit_selection()}
                    modalTitle={m.firewall_select_devices()}
                    toggleText={m.firewall_all_network_devices()}
                    toggleValue={allDevices}
                    onToggleChange={(value) =>
                      form.setFieldValue('all_network_devices', value)
                    }
                  />
                )}
              </form.AppField>
            </>
          )}
        </EditPageFormSection>

        <Divider spacing={ThemeSpacing.Xl2} />

        <EditPageFormSection label={m.firewall_section_destinations()}>
          <form.AppField name="any_destination">
            {(field) => <field.FormToggle label={m.firewall_label_any_destination()} />}
          </form.AppField>
          {!anyDestination && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="destinations">
                {(field) => (
                  <field.FormTextarea
                    required
                    label={m.firewall_label_destinations()}
                    helper={m.firewall_helper_destinations()}
                  />
                )}
              </form.AppField>
            </>
          )}
        </EditPageFormSection>

        <Divider spacing={ThemeSpacing.Xl2} />

        <EditPageFormSection label={m.firewall_section_services()}>
          <p className="field-label">{m.firewall_label_protocols()}</p>
          <form.AppField name="protocols">
            {(field) => (
              <field.FormCheckboxGroup
                values={[...COMMON_PROTOCOLS]}
                getLabel={protocolName}
              />
            )}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="ports">
            {(field) => (
              <field.FormInput
                label={m.firewall_label_ports()}
                helper={m.firewall_helper_ports()}
              />
            )}
          </form.AppField>
        </EditPageFormSection>

        <Divider spacing={ThemeSpacing.Xl2} />

        <EditPageFormSection label={m.firewall_section_locations()}>
          <form.AppField name="locations">
            {(field) => (
              <field.FormSelectMultiple
                options={locationOptions}
                counterText={counter}
                editText={m.firewall_edit_selection()}
                modalTitle={m.firewall_select_locations()}
                toggleText={m.firewall_all_locations()}
                toggleValue={allLocations}
                onToggleChange={(value) => form.setFieldValue('all_locations', value)}
              />
            )}
          </form.AppField>
        </EditPageFormSection>

        <SizedBox height={ThemeSpacing.Xl2} />

        <EditPageControls
          deleteProps={
            rule
              ? {
                  text: m.controls_delete(),
                  disabled: isSubmitting,
                  onClick: () =>
                    openModal(ModalName.ConfirmAction, {
                      title: m.firewall_delete_confirm_title(),
                      contentMd: m.firewall_delete_confirm_body({ name: rule.name }),
                      actionPromise: () => api.firewall.deleteRule(rule.id),
                      invalidateKeys: [['firewall']],
                      submitProps: { text: m.controls_delete(), variant: 'critical' },
                      onSuccess: () => {
                        Snackbar.default(m.firewall_delete_success());
                        navigate({ to: '/firewall', replace: true });
                      },
                      onError: () => Snackbar.error(m.firewall_delete_failed()),
                    }),
                }
              : undefined
          }
          cancelProps={{
            disabled: isSubmitting,
            onClick: () => navigate({ to: '/firewall' }),
          }}
          submitProps={{
            testId: 'submit',
            text: rule ? m.controls_save_changes() : m.firewall_add(),
            loading: isSubmitting,
            onClick: () => form.handleSubmit(),
          }}
        />
      </form.AppForm>
    </form>
  );
};
