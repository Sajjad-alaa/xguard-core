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
import { ageOptions, CHOICE_CUSTOM, versionOptions } from './choices';
import {
  type AgeField,
  emptyForm,
  type FormFields,
  formSchema,
  formToRequest,
  MAX_AGE_DAYS,
  postureToForm,
  type VersionField,
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
  | 'macos_antivirus'
  | 'macos_domain'
  | 'linux_disk_encryption'
  | 'linux_firewall'
  | 'linux_screen_lock'
  | 'linux_antivirus'
  | 'linux_domain'
  | 'ios_screen_lock'
  | 'ios_disk_encryption'
  | 'android_integrity'
  | 'android_screen_lock'
  | 'android_disk_encryption';

const ModalContent = ({
  posture,
  locations,
  versions,
}: OpenCEPostureCheckModal & Props) => {
  const [createdId, setCreatedId] = useState<number | null>(null);
  // Built once per opened modal: a catalog refetch must not reset what the admin typed.
  // biome-ignore lint/correctness/useExhaustiveDependencies: see above
  const defaultValues = useMemo(
    (): FormFields => (posture ? postureToForm(posture, versions) : emptyForm()),
    [posture],
  );

  const save = useMutation({
    mutationFn: async (values: FormFields) => {
      const request = formToRequest(values);
      const existingId = posture?.id ?? createdId;
      const savedId =
        existingId !== null
          ? (
              await api.devicePosture.editDevicePosture({
                id: existingId,
                ...request,
              })
            ).data.id
          : await (async () => {
              const saved = await api.devicePosture.addDevicePosture(request);
              setCreatedId(saved.data.id);
              return saved.data.id;
            })();
      await api.devicePosture.setLocationsForDevicePosture(savedId, values.locations);
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
  // Only the dropdown choices decide which custom inputs are shown.
  const values = useStore(form.store, (s) => ({
    min_desktop_client_version_choice: s.values.min_desktop_client_version_choice,
    min_mobile_client_version_choice: s.values.min_mobile_client_version_choice,
    windows_version_choice: s.values.windows_version_choice,
    macos_version_choice: s.values.macos_version_choice,
    linux_kernel_choice: s.values.linux_kernel_choice,
    ios_version_choice: s.values.ios_version_choice,
    android_version_choice: s.values.android_version_choice,
    windows_update_age_choice: s.values.windows_update_age_choice,
    macos_update_age_choice: s.values.macos_update_age_choice,
    linux_update_age_choice: s.values.linux_update_age_choice,
    android_patch_age_choice: s.values.android_patch_age_choice,
  }));

  const checkbox = (name: BoolField, text: string) => (
    <form.AppField name={name}>
      {(field) => <field.FormCheckbox text={text} />}
    </form.AppField>
  );
  const choiceLabels = {
    any: m.posture_checks_version_any(),
    custom: m.posture_checks_form_choice_custom(),
  };
  const ageLabels = {
    any: m.posture_checks_form_choice_any_age(),
    custom: m.posture_checks_form_choice_custom(),
    days: (days: number) => m.posture_checks_form_choice_days({ days }),
  };
  /** A version dropdown; "Custom…" reveals a text input for a version not in the list. */
  const versionSelect = (
    field: VersionField,
    label: string,
    options: DevicePostureVersionOption[] | undefined,
    customHelper: string,
  ) => (
    <div className="choice-field">
      <form.AppField name={`${field}_choice`}>
        {(choice) => (
          <choice.FormSelect
            label={label}
            options={versionOptions(options ?? [], choiceLabels)}
          />
        )}
      </form.AppField>
      {values[`${field}_choice`] === CHOICE_CUSTOM && (
        <form.AppField name={field}>
          {(custom) => (
            <custom.FormInput
              label={m.posture_checks_form_label_custom_version()}
              helper={customHelper}
            />
          )}
        </form.AppField>
      )}
    </div>
  );
  /** A day-count dropdown; "Custom…" reveals a number input. */
  const ageSelect = (field: AgeField, label: string) => (
    <div className="choice-field">
      <form.AppField name={`${field}_choice`}>
        {(choice) => <choice.FormSelect label={label} options={ageOptions(ageLabels)} />}
      </form.AppField>
      {values[`${field}_choice`] === CHOICE_CUSTOM && (
        <form.AppField name={field}>
          {(custom) => (
            <custom.FormInput
              type="number"
              label={m.posture_checks_form_label_custom_days()}
              helper={m.posture_checks_form_helper_custom_days({ max: MAX_AGE_DAYS })}
            />
          )}
        </form.AppField>
      )}
    </div>
  );
  const help = (text: string) => <p className="os-rule-help">{text}</p>;
  const clientHelper = m.posture_checks_form_helper_custom_client_version();
  const osHelper = m.posture_checks_form_helper_custom_version();
  const antivirus = m.posture_checks_condition_antivirus_edr();
  const directory = m.posture_checks_condition_directory();
  const updateAge = m.posture_checks_form_label_update_age();
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
          {versionSelect(
            'min_desktop_client_version',
            m.posture_checks_form_label_desktop_version(),
            versions.desktop_client,
            clientHelper,
          )}
          {versionSelect(
            'min_mobile_client_version',
            m.posture_checks_form_label_mobile_version(),
            versions.mobile_client,
            clientHelper,
          )}
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
            {versionSelect(
              'windows_version',
              m.posture_checks_form_label_os_version(),
              versions.windows,
              osHelper,
            )}
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
            {ageSelect('windows_update_age', updateAge)}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="macos">
          {(field) => <field.FormToggle label="macOS" />}
        </form.AppField>
        {enabled.macos && (
          <div className="os-rule">
            {versionSelect(
              'macos_version',
              m.posture_checks_form_label_os_version(),
              versions.macos,
              osHelper,
            )}
            {checkbox('macos_disk_encryption', disk)}
            {checkbox('macos_firewall', firewall)}
            {checkbox('macos_screen_lock', screenLock)}
            {checkbox('macos_integrity', integrity)}
            {checkbox('macos_antivirus', antivirus)}
            {checkbox('macos_domain', directory)}
            {ageSelect('macos_update_age', updateAge)}
            {help(m.posture_checks_form_help_macos())}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="linux">
          {(field) => <field.FormToggle label="Linux" />}
        </form.AppField>
        {enabled.linux && (
          <div className="os-rule">
            {versionSelect(
              'linux_kernel',
              m.posture_checks_form_label_kernel_version(),
              versions.linux_kernel,
              osHelper,
            )}
            {checkbox('linux_disk_encryption', disk)}
            {checkbox('linux_firewall', firewall)}
            {checkbox('linux_screen_lock', screenLock)}
            {checkbox('linux_antivirus', antivirus)}
            {checkbox('linux_domain', directory)}
            {ageSelect(
              'linux_update_age',
              m.posture_checks_form_label_linux_update_age(),
            )}
            {help(m.posture_checks_form_help_linux())}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="ios">
          {(field) => <field.FormToggle label="iOS" />}
        </form.AppField>
        {enabled.ios && (
          <div className="os-rule">
            {versionSelect(
              'ios_version',
              m.posture_checks_form_label_os_version(),
              versions.ios,
              osHelper,
            )}
            {checkbox('ios_screen_lock', m.posture_checks_condition_ios_passcode())}
            {checkbox(
              'ios_disk_encryption',
              m.posture_checks_condition_ios_data_protection(),
            )}
            {help(m.posture_checks_form_help_ios())}
          </div>
        )}

        <SizedBox height={ThemeSpacing.Lg} />
        <form.AppField name="android">
          {(field) => <field.FormToggle label="Android" />}
        </form.AppField>
        {enabled.android && (
          <div className="os-rule">
            {versionSelect(
              'android_version',
              m.posture_checks_form_label_os_version(),
              versions.android,
              osHelper,
            )}
            {checkbox('android_screen_lock', m.posture_checks_condition_android_lock())}
            {checkbox(
              'android_disk_encryption',
              m.posture_checks_condition_android_encryption(),
            )}
            {checkbox('android_integrity', integrity)}
            {ageSelect('android_patch_age', m.posture_checks_form_label_patch_age())}
            {help(m.posture_checks_form_help_android())}
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
