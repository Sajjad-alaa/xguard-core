import z from 'zod';
import { m } from '../../../../paraglide/messages';
import { useAppForm } from '../../../../shared/form';
import { formChangeLogic } from '../../../../shared/formLogic';
import { patternValidEmail } from '../../../../shared/patterns';
import { EvenSplit } from '../../../../shared/xguard-ui/components/EvenSplit/EvenSplit';
import { FieldError } from '../../../../shared/xguard-ui/components/FieldError/FieldError';
import { ModalControls } from '../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { runSmtpOAuthFlow } from './oauthFlow';
import type { FormProps } from './types';
import { useOAuthSubmit } from './useOAuthSubmit';

const createSchema = (storedSecret: boolean, storedClientId: string | null) =>
  z
    .object({
      smtp_sender: z
        .string()
        .trim()
        .min(1, m.form_error_required())
        .regex(patternValidEmail, m.form_error_email()),
      smtp_oauth_client_id: z.string().trim().min(1, m.form_error_required()),
      smtp_oauth_client_secret: z.string().trim().nullable().optional(),
      smtp_tls_verify_cert: z.boolean(),
    })
    .superRefine((value, ctx) => {
      const canReuseSecret =
        storedSecret &&
        Boolean(storedClientId) &&
        value.smtp_oauth_client_id === storedClientId;
      if (!value.smtp_oauth_client_secret && !canReuseSecret) {
        ctx.addIssue({
          code: 'custom',
          path: ['smtp_oauth_client_secret'],
          message: m.form_error_required(),
        });
      }
    });

type FormFields = z.infer<ReturnType<typeof createSchema>>;

export const GoogleAuthForm = ({
  initialValues,
  onOAuthConnected,
  onClose,
}: FormProps) => {
  const { oauthError, setOauthError, handleCancel, beginOAuth, handleOAuthError } =
    useOAuthSubmit(onClose);

  const schema = createSchema(
    initialValues.smtp_oauth_client_secret_set,
    initialValues.smtp_oauth_client_id,
  );

  const defaultValues: FormFields = {
    smtp_sender: initialValues.smtp_sender,
    smtp_oauth_client_id: initialValues.smtp_oauth_client_id ?? '',
    smtp_oauth_client_secret: initialValues.smtp_oauth_client_secret,
    smtp_tls_verify_cert: initialValues.smtp_tls_verify_cert,
  };

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: { onSubmit: schema, onChange: schema },
    onSubmit: async ({ value }) => {
      setOauthError(null);
      try {
        await runSmtpOAuthFlow(
          {
            provider: 'google',
            client_id: value.smtp_oauth_client_id.trim(),
            client_secret: value.smtp_oauth_client_secret?.trim() || undefined,
            sender: value.smtp_sender.trim(),
            tls_verify_cert: value.smtp_tls_verify_cert,
          },
          beginOAuth(),
        );
        await onOAuthConnected();
      } catch (err) {
        handleOAuthError(err);
      }
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.stopPropagation();
        e.preventDefault();
        form.handleSubmit();
      }}
    >
      <form.AppForm>
        <EvenSplit>
          <form.AppField name="smtp_sender">
            {(field) => (
              <field.FormInput
                required
                label={m.settings_smtp_label_sender_email_address()}
                helper={m.settings_smtp_helper_sender_email_address()}
              />
            )}
          </form.AppField>
        </EvenSplit>
        <SizedBox height={ThemeSpacing.Xl} />
        <EvenSplit>
          <form.AppField name="smtp_oauth_client_id">
            {(field) => (
              <field.FormInput
                required
                label={m.settings_smtp_label_oauth_client_id()}
                helper={m.settings_smtp_helper_oauth_client_id()}
              />
            )}
          </form.AppField>
          <form.AppField name="smtp_oauth_client_secret">
            {(field) => (
              <field.FormSecretInput
                required
                stored={initialValues.smtp_oauth_client_secret_set}
                label={m.settings_smtp_label_oauth_client_secret()}
                helper={m.settings_smtp_helper_oauth_client_secret()}
              />
            )}
          </form.AppField>
        </EvenSplit>
        <SizedBox height={ThemeSpacing.Md} />
        <form.AppField name="smtp_tls_verify_cert">
          {(field) => (
            <field.FormCheckbox
              text={m.settings_smtp_checkbox_verify_tls_certificate()}
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Md} />
        <p className="smtp-auth-oauth-info">{m.settings_smtp_auth_oauth_info()}</p>
        <FieldError error={oauthError} />
        <form.Subscribe selector={(s) => ({ isSubmitting: s.isSubmitting })}>
          {({ isSubmitting }) => (
            <ModalControls
              submitProps={{
                testId: 'submit',
                text: m.controls_submit(),
                loading: isSubmitting,
                onClick: () => form.handleSubmit(),
              }}
              cancelProps={{
                testId: 'cancel',
                text: m.controls_cancel(),
                onClick: handleCancel,
              }}
            />
          )}
        </form.Subscribe>
      </form.AppForm>
    </form>
  );
};
