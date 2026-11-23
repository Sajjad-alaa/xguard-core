import { useMutation } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import z from 'zod';
import { m } from '../../../../../paraglide/messages';
import api from '../../../../../shared/api/api';
import {
  type ActivityLogBodyFormat,
  type ActivityLogHeaderInput,
  ActivityLogStreamType,
  type ActivityLogStreamTypeValue,
  type CreateActivityLogStreamRequest,
  type SyslogFormat,
  type SyslogFraming,
} from '../../../../../shared/api/types';
import { useAppForm } from '../../../../../shared/form';
import { formChangeLogic } from '../../../../../shared/formLogic';
import {
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../../shared/hooks/modalControls/modalTypes';
import { processCertificateFile } from '../../../../../shared/utils/processCertificateFile';
import { Modal } from '../../../../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SectionSelect } from '../../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';

const modalNameValue = ModalName.AddLogStreaming;

type ModalState = {
  step: 'choice' | 'form';
  destination: ActivityLogStreamTypeValue | null;
};

const defaultState: ModalState = {
  step: 'choice',
  destination: null,
};

function parseCustomHeaders(raw: string): ActivityLogHeaderInput[] {
  const headers: ActivityLogHeaderInput[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const sep = trimmed.indexOf(':');
    if (sep <= 0) continue;
    const name = trimmed.slice(0, sep).trim();
    const value = trimmed.slice(sep + 1).trim();
    if (name) {
      headers.push(value ? { name, value } : { name });
    }
  }
  return headers;
}

export const AddLogStreamingModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalState, setModalState] = useState<ModalState>(defaultState);

  const modalTitle = useMemo(() => {
    if (modalState.step === 'choice')
      return m.modal_select_log_streaming_destination_title();
    switch (modalState.destination) {
      case ActivityLogStreamType.LogstashHttp:
        return m.modal_add_logstash_destination_title();
      case ActivityLogStreamType.VectorHttp:
        return m.modal_add_vector_destination_title();
      case ActivityLogStreamType.Syslog:
        return m.modal_add_syslog_destination_title();
      case ActivityLogStreamType.Http:
        return m.modal_add_http_destination_title();
      case ActivityLogStreamType.SplunkHec:
        return m.modal_add_splunk_destination_title();
      default:
        return m.modal_add_log_streaming_destination_title();
    }
  }, [modalState]);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalNameValue, () => {
      setOpen(true);
    });
    const closeSub = subscribeCloseModal(modalNameValue, () => setOpen(false));
    return () => {
      openSub.unsubscribe();
      closeSub.unsubscribe();
    };
  }, []);

  return (
    <Modal
      title={modalTitle}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => setModalState(defaultState)}
    >
      {modalState.step === 'choice' && <ChoiceStep setModalState={setModalState} />}
      {modalState.step === 'form' && modalState.destination && (
        <FormStep
          destination={modalState.destination}
          setOpen={setOpen}
          setModalState={setModalState}
        />
      )}
    </Modal>
  );
};

type ChoiceStepProps = {
  setModalState: (state: ModalState) => void;
};

const ChoiceStep = ({ setModalState }: ChoiceStepProps) => {
  const choose = (destination: ActivityLogStreamTypeValue) => {
    setModalState({ step: 'form', destination });
  };
  return (
    <>
      <SectionSelect
        image="gateway-notifications"
        title={m.modal_syslog_destination_title()}
        content={m.modal_add_syslog_destination()}
        data-testid="add-syslog"
        onClick={() => choose(ActivityLogStreamType.Syslog)}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <SectionSelect
        image="integrations"
        title={m.modal_http_destination_title()}
        content={m.modal_add_http_destination()}
        data-testid="add-http"
        onClick={() => choose(ActivityLogStreamType.Http)}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <SectionSelect
        image="id-providers"
        title={m.modal_splunk_destination_title()}
        content={m.modal_add_splunk_destination()}
        data-testid="add-splunk"
        onClick={() => choose(ActivityLogStreamType.SplunkHec)}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <SectionSelect
        image="logstash"
        title={m.modal_logstash_destination_title()}
        content={m.modal_add_logstash_destination()}
        data-testid="add-logstash"
        onClick={() => choose(ActivityLogStreamType.LogstashHttp)}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <SectionSelect
        image="vector"
        content={m.modal_add_vector_destination()}
        title={m.modal_vector_destination_title()}
        data-testid="add-vector"
        onClick={() => choose(ActivityLogStreamType.VectorHttp)}
      />
    </>
  );
};

type FormStepProps = {
  destination: ActivityLogStreamTypeValue;
  setOpen: (open: boolean) => void;
  setModalState: (state: ModalState) => void;
};

const bodyFormatOptions = [
  { key: 'json_array', value: 'json_array', label: 'JSON array (batched)' },
  { key: 'ndjson', value: 'ndjson', label: 'NDJSON (newline-delimited)' },
  { key: 'json', value: 'json', label: 'Single JSON object per request' },
];

const syslogFormatOptions = [
  { key: 'rfc5424', value: 'rfc5424', label: 'RFC 5424 (recommended)' },
  { key: 'rfc3164', value: 'rfc3164', label: 'RFC 3164 (legacy BSD)' },
];

const syslogFramingOptions = [
  { key: 'octet_counting', value: 'octet_counting', label: 'Octet counting (RFC 6587)' },
  { key: 'newline', value: 'newline', label: 'Newline delimited' },
];

const FormStep = ({ destination, setOpen }: FormStepProps) => {
  const { mutateAsync: createStream } = useMutation({
    mutationFn: api.activityLogStream.createStream,
    meta: {
      invalidate: [['activity_log_stream'], ['activity-log']],
    },
  });

  const isSyslog = destination === ActivityLogStreamType.Syslog;
  const isHttp = destination === ActivityLogStreamType.Http;
  const isSplunk = destination === ActivityLogStreamType.SplunkHec;
  const hasBasicAuth = !isSyslog && !isSplunk;

  const formSchema = useMemo(
    () =>
      z.object({
        name: z.string().trim().min(1, m.form_error_required()),
        url: z.string().trim().min(1, m.form_error_required()),
        username: z.string().nullable(),
        password: z.string().nullable(),
        certificate: z.file().nullable(),
        tls_verify: z.boolean(),
        body_format: z.string(),
        custom_headers: z.string(),
        syslog_format: z.string(),
        syslog_framing: z.string(),
        syslog_facility: z.string(),
        syslog_app_name: z.string(),
        syslog_hostname: z.string(),
        client_cert: z.file().nullable(),
        client_key: z.string(),
        token: z.string(),
        splunk_sourcetype: z.string(),
        splunk_source: z.string(),
        splunk_index: z.string(),
      }),
    [],
  );

  type FormFields = z.infer<typeof formSchema>;

  const defaultValues = useMemo(
    (): FormFields => ({
      name: '',
      url: isSyslog ? 'tls://siem.example.com:6514' : '',
      username: '',
      password: '',
      certificate: null,
      tls_verify: true,
      body_format: 'json_array',
      custom_headers: '',
      syslog_format: 'rfc5424',
      syslog_framing: 'octet_counting',
      syslog_facility: '16',
      syslog_app_name: 'xguard',
      syslog_hostname: '',
      client_cert: null,
      client_key: '',
      token: '',
      splunk_sourcetype: 'xguard:activity',
      splunk_source: '',
      splunk_index: '',
    }),
    [isSyslog],
  );

  const form = useAppForm({
    defaultValues,
    validationLogic: formChangeLogic,
    validators: {
      onSubmit: formSchema,
      onChange: formSchema,
    },
    onSubmit: async ({ value }) => {
      const certificateContent = await processCertificateFile(value.certificate);
      const clientCertContent = isSyslog
        ? await processCertificateFile(value.client_cert)
        : null;
      const isTlsUrl =
        value.url.trim().startsWith('https://') || value.url.trim().startsWith('tls://');

      const requestData: CreateActivityLogStreamRequest = {
        name: value.name,
        stream_type: destination,
        stream_config: {
          url: value.url,
          username: hasBasicAuth ? value.username : null,
          password: hasBasicAuth ? value.password : undefined,
          cert: certificateContent,
          tls_verify: isTlsUrl ? value.tls_verify : true,
          ...(isHttp
            ? {
                body_format: value.body_format as ActivityLogBodyFormat,
                headers: parseCustomHeaders(value.custom_headers),
              }
            : {}),
          ...(isSyslog
            ? {
                syslog: {
                  format: value.syslog_format as SyslogFormat,
                  framing: value.syslog_framing as SyslogFraming,
                  facility: Number.parseInt(value.syslog_facility, 10) || 16,
                  app_name: value.syslog_app_name.trim() || null,
                  hostname: value.syslog_hostname.trim() || null,
                },
                client_cert: clientCertContent,
                client_key: value.client_key.trim() || undefined,
              }
            : {}),
          ...(isSplunk
            ? {
                token: value.token,
                splunk: {
                  sourcetype: value.splunk_sourcetype.trim() || null,
                  source: value.splunk_source.trim() || null,
                  index: value.splunk_index.trim() || null,
                },
              }
            : {}),
        },
      };

      await createStream(requestData);
      setOpen(false);
    },
  });

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
                helper={m.modal_add_log_streaming_helper_name()}
              />
            )}
          </form.AppField>

          <SizedBox height={ThemeSpacing.Xl} />

          <form.AppField name="url">
            {(field) => (
              <field.FormInput
                required
                label={m.form_label_url()}
                helper={m.modal_add_log_streaming_helper_url()}
              />
            )}
          </form.AppField>

          {isHttp && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="body_format">
                {(field) => (
                  <field.FormSelect
                    label={m.modal_log_streaming_body_format()}
                    options={bodyFormatOptions}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="custom_headers">
                {(field) => (
                  <field.FormTextarea
                    label={m.modal_log_streaming_custom_headers()}
                    helper={m.modal_log_streaming_custom_headers_helper()}
                  />
                )}
              </form.AppField>
            </>
          )}

          {isSplunk && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="token">
                {(field) => (
                  <field.FormInput
                    required
                    type="password"
                    label={m.modal_log_streaming_splunk_token()}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="splunk_sourcetype">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_splunk_sourcetype()} />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="splunk_source">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_splunk_source()} />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="splunk_index">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_splunk_index()} />
                )}
              </form.AppField>
            </>
          )}

          {isSyslog && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="syslog_format">
                {(field) => (
                  <field.FormSelect
                    label={m.modal_log_streaming_syslog_format()}
                    options={syslogFormatOptions}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="syslog_framing">
                {(field) => (
                  <field.FormSelect
                    label={m.modal_log_streaming_syslog_framing()}
                    options={syslogFramingOptions}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="syslog_facility">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_syslog_facility()} />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="syslog_app_name">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_syslog_app_name()} />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="syslog_hostname">
                {(field) => (
                  <field.FormInput label={m.modal_log_streaming_syslog_hostname()} />
                )}
              </form.AppField>
            </>
          )}

          {hasBasicAuth && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="username">
                {(field) => (
                  <field.FormInput
                    label={m.form_label_username()}
                    helper={m.modal_add_log_streaming_helper_username()}
                  />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="password">
                {(field) => (
                  <field.FormInput
                    label={m.form_label_password()}
                    type="password"
                    helper={m.modal_add_log_streaming_helper_password()}
                  />
                )}
              </form.AppField>
            </>
          )}

          <SizedBox height={ThemeSpacing.Xl} />

          <form.AppField name="tls_verify">
            {(field) => <field.FormToggle label={m.modal_log_streaming_tls_verify()} />}
          </form.AppField>

          <SizedBox height={ThemeSpacing.Xl} />

          <form.AppField name="certificate">
            {(field) => (
              <field.FormUploadField
                title={m.settings_activity_log_streaming_upload_certificate_file()}
              />
            )}
          </form.AppField>

          {isSyslog && (
            <>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="client_cert">
                {(field) => (
                  <field.FormUploadField title={m.modal_log_streaming_client_cert()} />
                )}
              </form.AppField>
              <SizedBox height={ThemeSpacing.Xl} />
              <form.AppField name="client_key">
                {(field) => (
                  <field.FormTextarea label={m.modal_log_streaming_client_key()} />
                )}
              </form.AppField>
            </>
          )}
        </form.AppForm>
      </form>
      <ModalControls
        submitProps={{
          text: m.controls_submit(),
          testId: 'add-destination-submit',
          onClick: () => form.handleSubmit(),
        }}
        cancelProps={{
          text: m.controls_cancel(),
          onClick: () => setOpen(false),
        }}
      />
    </>
  );
};
