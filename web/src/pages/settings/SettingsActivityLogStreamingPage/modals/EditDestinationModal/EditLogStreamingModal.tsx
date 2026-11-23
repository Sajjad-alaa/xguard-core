import { useMutation } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import z from 'zod';
import { m } from '../../../../../paraglide/messages';
import api from '../../../../../shared/api/api';
import {
  type ActivityLogBodyFormat,
  type ActivityLogHeaderInput,
  type ActivityLogStream,
  ActivityLogStreamType,
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
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import { isPresent } from '../../../../../shared/xguard-ui/utils/isPresent';

const modalNameValue = ModalName.EditLogStreaming;

type ModalData = ActivityLogStream;

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

function parseCustomHeaders(raw: string): ActivityLogHeaderInput[] {
  const headers: ActivityLogHeaderInput[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const sep = trimmed.indexOf(':');
    if (sep <= 0) {
      headers.push({ name: trimmed });
      continue;
    }
    const name = trimmed.slice(0, sep).trim();
    const value = trimmed.slice(sep + 1).trim();
    if (name) {
      headers.push(value ? { name, value } : { name });
    }
  }
  return headers;
}

export const EditLogStreamingModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<ModalData | null>(null);

  const modalTitle = useMemo(() => {
    if (!modalData) return m.modal_edit_log_streaming_destination_title();
    switch (modalData.stream_type) {
      case ActivityLogStreamType.LogstashHttp:
        return m.modal_edit_logstash_destination_title();
      case ActivityLogStreamType.VectorHttp:
        return m.modal_edit_vector_destination_title();
      case ActivityLogStreamType.Syslog:
        return m.modal_edit_syslog_destination_title();
      case ActivityLogStreamType.Http:
        return m.modal_edit_http_destination_title();
      case ActivityLogStreamType.SplunkHec:
        return m.modal_edit_splunk_destination_title();
    }
  }, [modalData]);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalNameValue, (data: ModalData) => {
      setModalData(data);
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
      afterClose={() => setModalData(null)}
    >
      {isPresent(modalData) && (
        <ModalContent key={modalData.id} modalData={modalData} setOpen={setOpen} />
      )}
    </Modal>
  );
};

type ModalContentProps = {
  modalData: ModalData;
  setOpen: (open: boolean) => void;
};

const ModalContent = ({ modalData, setOpen }: ModalContentProps) => {
  const { mutateAsync: updateStream } = useMutation({
    mutationFn: ({ id, data }: { id: number; data: CreateActivityLogStreamRequest }) =>
      api.activityLogStream.updateStream(id, data),
    meta: {
      invalidate: [['activity_log_stream'], ['activity-log']],
    },
  });

  const isSyslog = modalData.stream_type === ActivityLogStreamType.Syslog;
  const isHttp = modalData.stream_type === ActivityLogStreamType.Http;
  const isSplunk = modalData.stream_type === ActivityLogStreamType.SplunkHec;
  const hasBasicAuth = !isSyslog && !isSplunk;

  const formSchema = useMemo(
    () =>
      z.object({
        name: z.string().trim().min(1, m.form_error_required()),
        url: z.string().trim().min(1, m.form_error_required()),
        username: z.string().nullable(),
        password: z.string().nullable().optional(),
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
        client_key: z.string().nullable().optional(),
        token: z.string().nullable().optional(),
        splunk_sourcetype: z.string(),
        splunk_source: z.string(),
        splunk_index: z.string(),
      }),
    [],
  );

  type FormFields = z.infer<typeof formSchema>;

  const defaultValues = useMemo(
    (): FormFields => ({
      name: modalData.name,
      url: modalData.url,
      username: modalData.username,
      password: undefined,
      certificate: modalData.cert ? new File([modalData.cert], 'certificate.pem') : null,
      tls_verify: modalData.tls_verify,
      body_format: modalData.body_format ?? 'json_array',
      custom_headers: modalData.headers.map((h) => `${h.name}:`).join('\n'),
      syslog_format: modalData.syslog?.format ?? 'rfc5424',
      syslog_framing: modalData.syslog?.framing ?? 'octet_counting',
      syslog_facility: String(modalData.syslog?.facility ?? 16),
      syslog_app_name: modalData.syslog?.app_name ?? 'xguard',
      syslog_hostname: modalData.syslog?.hostname ?? '',
      client_cert: modalData.client_cert
        ? new File([modalData.client_cert], 'client-cert.pem')
        : null,
      client_key: undefined,
      token: undefined,
      splunk_sourcetype: modalData.splunk?.sourcetype ?? 'xguard:activity',
      splunk_source: modalData.splunk?.source ?? '',
      splunk_index: modalData.splunk?.index ?? '',
    }),
    [modalData],
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
        stream_type: modalData.stream_type,
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
                client_key: value.client_key,
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

      await updateStream({ id: modalData.id, data: requestData });
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
                  <field.FormSecretInput
                    stored={modalData.token_set}
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
                  <field.FormSecretInput
                    stored={modalData.password_set}
                    label={m.form_label_password()}
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
                  <field.FormSecretInput
                    stored={modalData.client_key_set}
                    label={m.modal_log_streaming_client_key()}
                  />
                )}
              </form.AppField>
            </>
          )}
        </form.AppForm>
      </form>
      <ModalControls
        submitProps={{
          text: m.controls_save_changes(),
          testId: 'edit-destination-submit',
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
