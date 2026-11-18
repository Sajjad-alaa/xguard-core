import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ProvisioningFile } from '../src/shared/api/types';
import {
  downloadProvisioningFile,
  provisioningFileContent,
} from '../src/shared/utils/provisioning';

const file: ProvisioningFile = {
  version: 1,
  instance_name: 'XGuard',
  enrollment_url: 'https://edge.example.com/',
  enrollment_token: 'token123',
  expires_at: '2026-11-19T10:00:00Z',
  username: 'hpotter',
};

describe('provisioning file', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('serializes exactly the fields the client reads', () => {
    const content = provisioningFileContent({
      ...file,
      // Unknown fields from a newer server are not written to the file.
      ...({ extra: 'x' } as object),
    } as ProvisioningFile);
    expect(content.endsWith('\n')).toBe(true);
    expect(JSON.parse(content)).toEqual(file);
  });

  it('downloads as provisioning.json', () => {
    const createObjectURL = vi.fn(() => 'blob:x');
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {});
    let downloaded = '';
    const appendChild = document.body.appendChild.bind(document.body);
    vi.spyOn(document.body, 'appendChild').mockImplementation((node) => {
      downloaded = (node as HTMLAnchorElement).download;
      return appendChild(node);
    });
    downloadProvisioningFile(file);
    expect(click).toHaveBeenCalledTimes(1);
    expect(downloaded).toBe('provisioning.json');
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});
