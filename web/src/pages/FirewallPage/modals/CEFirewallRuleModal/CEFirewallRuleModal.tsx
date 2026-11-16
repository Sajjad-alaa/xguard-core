import './style.scss';
import { useStore } from '@tanstack/react-form';
import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { useEffect, useMemo, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import { FirewallRuleAction } from '../../../../shared/api/types';
import { DescriptionBlock } from '../../../../shared/components/DescriptionBlock/DescriptionBlock';
import { useAppForm } from '../../../../shared/form';
import { formChangeLogic } from '../../../../shared/formLogic';
import {
  closeModal,
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../shared/hooks/modalControls/modalTypes';
import type { OpenCEFirewallRuleModal } from '../../../../shared/hooks/modalControls/types';
import { Divider } from '../../../../shared/xguard-ui/components/Divider/Divider';
import { Modal } from '../../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { isPresent } from '../../../../shared/xguard-ui/utils/isPresent';
import { actionLabel, protocolName } from '../../summary';
import type { FirewallNames } from '../../useFirewallNames';
import {
  COMMON_PROTOCOLS,
  emptyForm,
  type FormFields,
  formSchema,
  formToInput,
  ruleToForm,
} from './form';

const modalName = ModalName.CEFirewallRule;

type Props = {
  names: FirewallNames;
};

export const CEFirewallRuleModal = ({ names }: Props) => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenCEFirewallRuleModal | null>(null);
  const isEdit = isPresent(modalData?.rule);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalName, (data) => {
      setModalData(data);
      setOpen(true);
    });
    const closeSub = subscribeCloseModal(modalName, () => setOpen(false));
    return () => {
      openSub.unsubscribe();
      closeSub.unsubscribe();
    };
  }, []);

  return (
    <Modal
      id="ce-firewall-rule-modal"
      title={isEdit ? m.firewall_modal_edit_title() : m.firewall_modal_create_title()}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => setModalData(null)}
    >
      {isPresent(modalData) && <ModalContent {...modalData} names={names} />}
    </Modal>
  );
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

const ModalContent = ({ rule, names }: OpenCEFirewallRuleModal & Props) => {
  const defaultValues = useMemo(
    (): FormFields => (rule ? ruleToForm(rule) : emptyForm()),
    [rule],
  );

  const mutationOptions = {
    meta: { invalidate: [['firewall']] },
    onSuccess: () => {
      Snackbar.success(m.firewall_save_success());
      closeModal(modalName);
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
        // Reported by the mutation's onError; keep the modal open for corrections.
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
      className="ce-firewall-rule-form"
      onSubmit={(e) => {
        e.stopPropagation();
        e.preventDefault();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <DescriptionBlock title={m.firewall_section_general()} />
        <SizedBox height={ThemeSpacing.Lg} />
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

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.firewall_section_sources()}>
          <p>{m.firewall_section_sources_text()}</p>
        </DescriptionBlock>
        <SizedBox height={ThemeSpacing.Lg} />
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
            <p className="label">{m.firewall_label_groups()}</p>
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

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.firewall_section_destinations()} />
        <SizedBox height={ThemeSpacing.Lg} />
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
        <SizedBox height={ThemeSpacing.Xl} />
        <p className="label">{m.firewall_label_protocols()}</p>
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

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.firewall_section_locations()} />
        <SizedBox height={ThemeSpacing.Lg} />
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

        <ModalControls
          cancelProps={{
            disabled: isSubmitting,
            text: m.controls_cancel(),
            onClick: () => closeModal(modalName),
          }}
          submitProps={{
            testId: 'submit',
            text: rule ? m.controls_save_changes() : m.controls_submit(),
            loading: isSubmitting,
            onClick: () => form.handleSubmit(),
          }}
        >
          <form.AppField name="enabled">
            {(field) => <field.FormToggle label={m.firewall_label_enabled()} />}
          </form.AppField>
        </ModalControls>
      </form.AppForm>
    </form>
  );
};
