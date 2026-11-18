import type { ProvisioningFile } from '../api/types';
import { downloadFile } from './download';

/** Name the XGuard desktop client looks for. */
export const PROVISIONING_FILE_NAME = 'provisioning';

/** File contents exactly as the desktop client parses them. */
export const provisioningFileContent = (file: ProvisioningFile): string =>
  `${JSON.stringify(
    {
      version: file.version,
      instance_name: file.instance_name,
      enrollment_url: file.enrollment_url,
      enrollment_token: file.enrollment_token,
      expires_at: file.expires_at,
      username: file.username,
    },
    null,
    2,
  )}\n`;

export const downloadProvisioningFile = (file: ProvisioningFile) => {
  const blob = new Blob([provisioningFileContent(file)], {
    type: 'application/json;charset=utf-8',
  });
  downloadFile(blob, PROVISIONING_FILE_NAME, 'json');
};
