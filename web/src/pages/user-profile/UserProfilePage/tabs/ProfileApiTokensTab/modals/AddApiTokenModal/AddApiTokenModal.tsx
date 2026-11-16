import { useStore } from '@tanstack/react-form';
import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { useEffect, useMemo, useState } from 'react';
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
import type { OpenAddApiTokenModal } from '../../../../../../../shared/hooks/modalControls/types';
import { CopyField } from '../../../../../../../shared/xguard-ui/components/CopyField/CopyField';
import { IconKind } from '../../../../../../../shared/xguard-ui/components/Icon';
import { InfoBanner } from '../../../../../../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import { Modal } from '../../../../../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../../../../shared/xguard-ui/types';
import { isPresent } from '../../../../../../../shared/xguard-ui/utils/isPresent';
import {
  type AddTokenFields,
  addTokenSchema,
  DEFAULT_EXPIRY,
  expiryOptions,
  toAddRequest,
} from '../../apiTokens';

const modalNameKey = ModalName.AddApiToken;

export const AddApiTokenModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenAddApiTokenModal | null>(null);

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
      id="add-api-token-modal"
      title={m.modal_add_api_title()}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => {
        setModalData(null);
      }}
    >
      {isPresent(modalData) && <ModalContent {...modalData} />}
    </Modal>
  );
};

const defaultValues: AddTokenFields = {
  name: '',
  expiry: DEFAULT_EXPIRY,
  read_only: false,
};

const errorMessage = (error: unknown) =>
  axios.isAxiosError(error) && typeof error.response?.data?.msg === 'string'
    ? error.response.data.msg
    : m.modal_add_api_token_failed();

const ModalContent = ({ username }: OpenAddApiTokenModal) => {
  const [token, setToken] = useState<string | null>(null);

  const { mutateAsync } = useMutation({
    mutationFn: api.user.addApiToken,
    meta: {
      invalidate: [['user', username, 'api_token']],
    },
    onSuccess: (response) => {
      setToken(response.data.token);
    },
    onError: (error) => Snackbar.error(errorMessage(error)),
  });
  const options = useMemo(() => [...expiryOptions()], []);

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: {
      onSubmit: addTokenSchema,
      onChange: addTokenSchema,
    },
    onSubmit: async ({ value }) => {
      try {
        await mutateAsync(toAddRequest(username, value));
      } catch {
        // Reported by onError; the form stays open for corrections.
      }
    },
  });

  const isSubmitting = useStore(form.store, (s) => s.isSubmitting);

  if (isPresent(token)) {
    return (
      <>
        <InfoBanner
          icon={IconKind.WarningOutlined}
          variant="warning"
          text={m.modal_add_api_token_copy_warning()}
        />
        <SizedBox height={ThemeSpacing.Xl2} />
        <CopyField
          copyTooltip={m.misc_clipboard_copy()}
          text={token}
          data-testid="copy-field"
          label={m.modal_add_api_token_copy_copy_label()}
        />
        <SizedBox height={ThemeSpacing.Md} />
        <p className="api-token-usage">{m.modal_add_api_token_usage()}</p>
        <ModalControls
          submitProps={{
            testId: 'close',
            text: m.controls_close(),
            onClick: () => {
              closeModal(modalNameKey);
            },
          }}
        />
      </>
    );
  }

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
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="expiry">
            {(field) => (
              <field.FormSelect
                required
                label={m.modal_add_api_token_expiry_label()}
                helper={m.modal_add_api_token_expiry_helper()}
                options={options}
              />
            )}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="read_only">
            {(field) => (
              <field.FormToggle label={m.modal_add_api_token_read_only_label()} />
            )}
          </form.AppField>
        </form.AppForm>
      </form>
      <ModalControls
        cancelProps={{
          testId: 'cancel',
          disabled: isSubmitting,
          text: m.controls_cancel(),
          onClick: () => {
            closeModal(modalNameKey);
          },
        }}
        submitProps={{
          testId: 'submit',
          text: m.controls_submit(),
          loading: isSubmitting,
          onClick: () => {
            form.handleSubmit();
          },
        }}
      />
    </>
  );
};
