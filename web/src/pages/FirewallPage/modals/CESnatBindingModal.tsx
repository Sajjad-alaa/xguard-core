import { useStore } from '@tanstack/react-form';
import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { useEffect, useMemo, useState } from 'react';
import z from 'zod';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { useAppForm } from '../../../shared/form';
import { formChangeLogic } from '../../../shared/formLogic';
import {
  closeModal,
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../shared/hooks/modalControls/modalTypes';
import type { OpenCESnatBindingModal } from '../../../shared/hooks/modalControls/types';
import { Modal } from '../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { isPresent } from '../../../shared/xguard-ui/utils/isPresent';
import type { FirewallNames } from '../useFirewallNames';

const modalName = ModalName.CESnatBinding;

type Props = { names: FirewallNames };

export const CESnatBindingModal = ({ names }: Props) => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenCESnatBindingModal | null>(null);

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
      id="ce-snat-binding-modal"
      title={
        isPresent(modalData?.binding)
          ? m.firewall_snat_modal_edit_title()
          : m.firewall_snat_modal_create_title()
      }
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => setModalData(null)}
    >
      {isPresent(modalData) && <ModalContent {...modalData} names={names} />}
    </Modal>
  );
};

const schema = z.object({
  user_id: z.number(m.form_error_required()),
  location_id: z.number(m.form_error_required()),
  public_ip: z.string().trim().min(1, m.form_error_required()),
});

const errorMessage = (error: unknown) =>
  axios.isAxiosError(error) && typeof error.response?.data?.msg === 'string'
    ? error.response.data.msg
    : m.firewall_snat_save_failed();

const ModalContent = ({ binding, names }: OpenCESnatBindingModal & Props) => {
  const userOptions = useMemo(
    () => names.users.map((u) => ({ key: u.id, label: u.label, value: u.id })),
    [names.users],
  );
  const locationOptions = useMemo(
    () => names.locations.map((l) => ({ key: l.id, label: l.label, value: l.id })),
    [names.locations],
  );

  const mutationOptions = {
    meta: { invalidate: [['firewall']] },
    onSuccess: () => {
      Snackbar.success(m.firewall_snat_saved());
      closeModal(modalName);
    },
    onError: (error: unknown) => Snackbar.error(errorMessage(error)),
  };
  const { mutateAsync: add } = useMutation({
    mutationFn: api.firewall.addSnatBinding,
    ...mutationOptions,
  });
  const { mutateAsync: edit } = useMutation({
    mutationFn: api.firewall.editSnatBinding,
    ...mutationOptions,
  });

  const form = useAppForm({
    defaultValues: {
      user_id: binding?.user_id ?? (userOptions[0]?.value as number),
      location_id: binding?.location_id ?? (locationOptions[0]?.value as number),
      public_ip: binding?.public_ip ?? '',
    },
    validationLogic: formChangeLogic,
    validators: { onSubmit: schema, onChange: schema },
    onSubmit: async ({ value }) => {
      try {
        if (binding) {
          await edit({ id: binding.id, public_ip: value.public_ip.trim() });
        } else {
          await add({ ...value, public_ip: value.public_ip.trim() });
        }
      } catch {
        // Reported by the mutation's onError; keep the modal open for corrections.
      }
    },
  });
  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);

  return (
    <form
      onSubmit={(e) => {
        e.stopPropagation();
        e.preventDefault();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <form.AppField name="user_id">
          {(field) => (
            <field.FormSelect
              required
              label={m.firewall_snat_label_user()}
              options={userOptions}
              disabled={isPresent(binding)}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="location_id">
          {(field) => (
            <field.FormSelect
              required
              label={m.firewall_snat_label_location()}
              options={locationOptions}
              disabled={isPresent(binding)}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Xl} />
        <form.AppField name="public_ip">
          {(field) => (
            <field.FormInput
              required
              label={m.firewall_snat_label_ip()}
              helper={m.firewall_snat_helper_ip()}
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
            text: binding ? m.controls_save_changes() : m.controls_submit(),
            loading: isSubmitting,
            onClick: () => form.handleSubmit(),
          }}
        />
      </form.AppForm>
    </form>
  );
};
