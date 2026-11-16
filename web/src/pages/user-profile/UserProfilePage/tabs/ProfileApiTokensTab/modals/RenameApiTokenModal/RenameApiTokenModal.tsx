import { useStore } from '@tanstack/react-form';
import { useMutation } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import z from 'zod';
import { m } from '../../../../../../../paraglide/messages';
import api from '../../../../../../../shared/api/api';
import { useAppForm } from '../../../../../../../shared/form';
import { formChangeLogic } from '../../../../../../../shared/formLogic';
import {
  closeModal,
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../../../../shared/hooks/modalControls/modalTypes';
import type { OpenRenameApiTokenModal } from '../../../../../../../shared/hooks/modalControls/types';
import { Modal } from '../../../../../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { Snackbar } from '../../../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { isPresent } from '../../../../../../../shared/xguard-ui/utils/isPresent';
import { tokenNameSchema } from '../../apiTokens';

const modalNameKey = ModalName.RenameApiToken;

export const RenameApiTokenModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenRenameApiTokenModal | null>(null);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalNameKey, (data) => {
      setModalData(data);
      setOpen(true);
    });
    const closeSub = subscribeCloseModal(modalNameKey, () => setOpen(false));
    return () => {
      openSub.unsubscribe();
      closeSub.unsubscribe();
    };
  }, []);

  return (
    <Modal
      title={m.modal_rename_api_title()}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
    >
      {isPresent(modalData) && <ModalContent {...modalData} />}
    </Modal>
  );
};

const formSchema = z.object({
  name: tokenNameSchema,
});

const ModalContent = ({ id, name, username }: OpenRenameApiTokenModal) => {
  const { mutateAsync } = useMutation({
    mutationFn: api.user.renameApiToken,
    meta: {
      invalidate: [['user', username, 'api_token']],
    },
    onSuccess: () => {
      closeModal(modalNameKey);
    },
    onError: () => Snackbar.error(m.modal_rename_api_token_failed()),
  });

  const form = useAppForm({
    defaultValues: {
      name,
    },
    validationLogic: formChangeLogic,
    validators: {
      onSubmit: formSchema,
      onChange: formSchema,
    },
    onSubmit: async ({ value }) => {
      try {
        await mutateAsync({
          id,
          name: value.name.trim(),
          username,
        });
      } catch {
        // Reported by onError; the form stays open for corrections.
      }
    },
  });

  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);

  return (
    <>
      <form
        onSubmit={(e) => {
          e.stopPropagation();
          e.preventDefault();
          form.handleSubmit();
        }}
      >
        <form.AppForm>
          <form.AppField name="name">
            {(field) => (
              <field.FormInput
                required
                label={m.form_label_name()}
                helper={m.form_helper_name()}
              />
            )}
          </form.AppField>
        </form.AppForm>
      </form>
      <ModalControls
        cancelProps={{
          disabled: isSubmitting,
          text: m.controls_cancel(),
          onClick: () => {
            closeModal(modalNameKey);
          },
        }}
        submitProps={{
          text: m.controls_save_changes(),
          loading: isSubmitting,
          onClick: () => {
            form.handleSubmit();
          },
        }}
      />
    </>
  );
};
