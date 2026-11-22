import type { ComponentType } from 'react';
import { m } from '../../../../paraglide/messages';
import { Modal } from '../../../../shared/xguard-ui/components/Modal/Modal';
import type { SmtpAuthCardVariant } from '../components/SmtpAuthMethodCard/SmtpAuthMethodCard';
import { BasicAuthForm } from './BasicAuthForm';
import { GoogleAuthForm } from './GoogleAuthForm';
import { MicrosoftAuthForm } from './MicrosoftAuthForm';
import { NoneAuthForm } from './NoneAuthForm';
import type { FormProps, SmtpAuthApplyResult, SmtpAuthModalValues } from './types';

export type { SmtpAuthApplyResult, SmtpAuthModalValues } from './types';

type Props = {
  isOpen: boolean;
  variant: SmtpAuthCardVariant | null;
  initialValues: SmtpAuthModalValues;
  onApply: (result: SmtpAuthApplyResult) => Promise<void>;
  onOAuthConnected: () => Promise<void>;
  onClose: () => void;
};

const modalTitles: Record<SmtpAuthCardVariant, () => string> = {
  none: m.settings_smtp_auth_modal_none_title,
  basic: m.settings_smtp_auth_modal_basic_title,
  custom: m.settings_smtp_auth_modal_custom_title,
  google: m.settings_smtp_auth_modal_google_title,
  microsoft: m.settings_smtp_auth_modal_microsoft_title,
};

const forms: Partial<Record<SmtpAuthCardVariant, ComponentType<FormProps>>> = {
  none: NoneAuthForm,
  basic: BasicAuthForm,
  google: GoogleAuthForm,
  microsoft: MicrosoftAuthForm,
};

export const SmtpAuthConfigModal = ({
  isOpen,
  variant,
  initialValues,
  onApply,
  onOAuthConnected,
  onClose,
}: Props) => {
  const FormComponent = variant ? forms[variant] : null;
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={variant ? modalTitles[variant]() : ''}
      size="primary"
    >
      {variant && FormComponent && (
        <FormComponent
          key={variant}
          initialValues={initialValues}
          onApply={onApply}
          onOAuthConnected={onOAuthConnected}
          onClose={onClose}
        />
      )}
    </Modal>
  );
};
