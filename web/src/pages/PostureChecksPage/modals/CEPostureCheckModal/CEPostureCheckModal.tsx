import './style.scss';
import { useStore } from '@tanstack/react-form';
import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { useEffect, useMemo, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import type {
  DevicePostureVersionCatalog,
  DevicePostureVersionOption,
} from '../../../../shared/api/types';
import { DescriptionBlock } from '../../../../shared/components/DescriptionBlock/DescriptionBlock';
import { useAppForm } from '../../../../shared/form';
import { formChangeLogic } from '../../../../shared/formLogic';
import {
  closeModal,
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../shared/hooks/modalControls/modalTypes';
import type { OpenCEPostureCheckModal } from '../../../../shared/hooks/modalControls/types';
import { Divider } from '../../../../shared/xguard-ui/components/Divider/Divider';
import { Modal } from '../../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { isPresent } from '../../../../shared/xguard-ui/utils/isPresent';
import {
  emptyForm,
  type FormFields,
  formSchema,
  formToRequest,
  postureToForm,
} from './form';

const modalName = ModalName.CEPostureCheck;

type Props = {
  locations: { id: number; label: string }[];
  versions: DevicePostureVersionCatalog;
};

export const CEPostureCheckModal = (props: Props) => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenCEPostureCheckModal | null>(null);
  const isEdit = isPresent(modalData?.posture);

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
      id="ce-posture-check-modal"
      title={
        isEdit
          ? m.posture_checks_modal_edit_title()
          : m.posture_checks_modal_create_title()
      }
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => setModalData(null)}
    >
      {isPresent(modalData) && <ModalContent {...modalData} {...props} />}
    </Modal>
  );
};

const errorMessage = (error: unknown) =>
  axios.isAxiosError(error) && typeof error.response?.data?.msg === 'string'
    ? error.response.data.msg
    : m.posture_checks_save_failed();

const examples = (options: DevicePostureVersionOption[]) =>
  m.posture_checks_form_helper_versions({
    examples: options
      .slice(-3)
      .map((option) => `${option.value} (${option.label})`)
      .join(', '),
  });

type BoolField =
  | 'windows_disk_encryption'
  | 'windows_firewall'
  | 'windows_screen_lock'
  | 'windows_antivirus'
  | 'windows_domain'
  | 'macos_disk_encryption'
  | 'macos_firewall'
  | 'macos_screen_lock'
  | 'macos_integrity'
  | 'linux_disk_encryption'
  | 'linux_firewall'
  | 'linux_screen_lock'
  | 'android_integrity';

const ModalContent = ({
  posture,
  locations,
  versions,
}: OpenCEPostureCheckModal & Props) => {
  const defaultValues = useMemo(
    (): FormFields => (posture ? postureToForm(posture) : emptyForm()),
    [posture],
  );

  const save = useMutation({
    mutationFn: async (values: FormFields) => {
      const request = formToRequest(values);
      const saved = posture
        ? await api.devicePosture.editDevicePosture({ id: posture.id, ...request })
        : await api.devicePosture.addDevicePosture(request);
      await api.devicePosture.setLocationsForDevicePosture(
        saved.data.id,
        values.locations,
      );
    },
    meta: { invalidate: [['device-posture'], ['network']] },
    onSuccess: () => {
      Snackbar.success(m.posture_checks_save_success());
      closeModal(modalName);
    },
    onError: (error: unknown) => Snackbar.error(errorMessage(error)),
  });

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: {
      onSubmit: formSchema,
      onChange: formSchema,
    },
    onSubmit: async ({ value }) => {
      try {
        await save.mutateAsync(value);
      } catch {
        // Reported by the mutation's onError; keep the modal open for corrections.
      }
    },
  });

  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);
  const enabled = useStore(form.store, (s) => ({
    windows: s.values.windows,
    macos: s.values.macos,
    linux: s.values.linux,
    ios: s.values.ios,
    android: s.values.android,
  }));

  const checkbox = (name: BoolField, text: string) => (
    <form.AppField name={name}>
      {(field) => <field.FormCheckbox text={text} />}
    </form.AppField>
  );
  const disk = m.posture_checks_wizard_operating_systems_condition_disk_encryption();
  const firewall = m.posture_checks_condition_firewall();
  const screenLock = m.posture_checks_condition_screen_lock();
  const integrity =
    m.posture_checks_wizard_operating_systems_condition_device_integrity();

  return (
    <form
      className="ce-posture-check-form"
      onSubmit={(e) => {
        e.stopPropagation();
        e.preventDefault();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <DescriptionBlock title={m.posture_checks_form_section_general()} />
        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="name">
          {(field) => (
            <field.FormInput required label={m.posture_checks_form_label_name()} />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="description">
          {(field) => (
            <field.FormTextarea label={m.posture_checks_form_label_description()} />
          )}
        </form.AppField>

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.posture_checks_form_section_client()} />
        <SizedBox height={ThemeSpacing.Lg} />
        <div className="row">
          <form.AppField name="min_desktop_client_version">
            {(field) => (
              <field.FormInput
                label={m.posture_checks_form_label_desktop_version()}
                helper={m.posture_checks_form_helper_client_version()}
              />
            )}
          </form.AppField>
          <form.AppField name="min_mobile_client_version">
            {(field) => (
              <field.FormInput
                label={m.posture_checks_form_label_mobile_version()}
                helper={m.posture_checks_form_helper_client_version()}
              />
            )}
          </form.AppField>
        </div>
        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="allow_prerelease_client">
          {(field) => (
            <field.FormToggle label={m.posture_checks_wizard_summary_prerelease()} />
          )}
        </form.AppField>

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.posture_checks_form_section_systems()}>
          <p>{m.posture_checks_form_section_systems_text()}</p>
        </DescriptionBlock>

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="windows">
          {(field) => <field.FormToggle label="Windows" />}
        </form.AppField>
        {enabled.windows && (
          <div className="os-rule">
            <form.AppField name="windows_version">
              {(field) => (
                <field.FormInput
                  label={m.posture_checks_form_label_os_version()}
                  helper={examples(versions.windows)}
                />
              )}
            </form.AppField>
            {checkbox('windows_disk_encryption', disk)}
            {checkbox('windows_firewall', firewall)}
            {checkbox('windows_screen_lock', screenLock)}
            {checkbox(
              'windows_antivirus',
              m.posture_checks_wizard_operating_systems_condition_antivirus(),
            )}
            {checkbox(
              'windows_domain',
              m.posture_checks_wizard_operating_systems_condition_active_directory(),
            )}
            <form.AppField name="windows_update_age">
              {(field) => (
                <field.FormInput
                  type="number"
                  label={m.posture_checks_form_label_update_age()}
                />
              )}
            </form.AppField>
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="macos">
          {(field) => <field.FormToggle label="macOS" />}
        </form.AppField>
        {enabled.macos && (
          <div className="os-rule">
            <form.AppField name="macos_version">
              {(field) => (
                <field.FormInput
                  label={m.posture_checks_form_label_os_version()}
                  helper={examples(versions.macos)}
                />
              )}
            </form.AppField>
            {checkbox('macos_disk_encryption', disk)}
            {checkbox('macos_firewall', firewall)}
            {checkbox('macos_screen_lock', screenLock)}
            {checkbox('macos_integrity', integrity)}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="linux">
          {(field) => <field.FormToggle label="Linux" />}
        </form.AppField>
        {enabled.linux && (
          <div className="os-rule">
            <form.AppField name="linux_kernel">
              {(field) => (
                <field.FormInput
                  label={m.posture_checks_form_label_kernel_version()}
                  helper={examples(versions.linux_kernel)}
                />
              )}
            </form.AppField>
            {checkbox('linux_disk_encryption', disk)}
            {checkbox('linux_firewall', firewall)}
            {checkbox('linux_screen_lock', screenLock)}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="ios">
          {(field) => <field.FormToggle label="iOS" />}
        </form.AppField>
        {enabled.ios && (
          <div className="os-rule">
            <form.AppField name="ios_version">
              {(field) => (
                <field.FormInput
                  label={m.posture_checks_form_label_os_version()}
                  helper={examples(versions.ios)}
                />
              )}
            </form.AppField>
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="android">
          {(field) => <field.FormToggle label="Android" />}
        </form.AppField>
        {enabled.android && (
          <div className="os-rule">
            <form.AppField name="android_version">
              {(field) => (
                <field.FormInput
                  label={m.posture_checks_form_label_os_version()}
                  helper={examples(versions.android)}
                />
              )}
            </form.AppField>
            {checkbox('android_integrity', integrity)}
            <form.AppField name="android_patch_age">
              {(field) => (
                <field.FormInput
                  type="number"
                  label={m.posture_checks_form_label_patch_age()}
                />
              )}
            </form.AppField>
          </div>
        )}

        <Divider spacing={ThemeSpacing.Xl} />
        <DescriptionBlock title={m.posture_checks_form_section_locations()} />
        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="locations">
          {(field) => (
            <field.FormSelectMultiple
              options={locations}
              counterText={(count: number) => `+${count}`}
              editText={m.posture_checks_form_edit_locations()}
              modalTitle={m.posture_checks_form_select_locations()}
              toggleValue={false}
              onToggleChange={() => {}}
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
            text: posture ? m.controls_save_changes() : m.controls_submit(),
            loading: isSubmitting,
            onClick: () => form.handleSubmit(),
          }}
        />
      </form.AppForm>
    </form>
  );
};
