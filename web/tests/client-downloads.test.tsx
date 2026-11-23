import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import type { AxiosResponse } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateClientDownloadForm } from '../src/pages/settings/SettingsClientDownloadsPage/SettingsClientDownloadsPage';
import api from '../src/shared/api/api';
import {
  assetUrl,
  buildClientDownloadLinks,
  type ClientDownloadSettings,
  type ClientDownloadsResponse,
  checkClientDownloadUrl,
  clientAssetNames,
  defaultClientDownloadSettings,
  linuxDownloadItems,
  mobileDownloadItems,
} from '../src/shared/clientDownloads';
import { AddDeviceModalClientConfigStep } from '../src/shared/components/modals/AddUserDeviceModal/steps/AddDeviceModalClientConfigStep/AddDeviceModalClientConfigStep';
import { useAddUserDeviceModal } from '../src/shared/components/modals/AddUserDeviceModal/store/useAddUserDeviceModal';
import {
  contextualHelpQueryOptions,
  videoTutorialsQueryOptions,
} from '../src/shared/query';

const github = 'https://github.com/Sajjad-alaa/xguard-client/releases/latest';

describe('buildClientDownloadLinks', () => {
  it('uses the GitHub latest release by default', () => {
    const links = buildClientDownloadLinks();
    expect(links).toEqual({
      debAmd64: `${github}/download/xguard-client_amd64.deb`,
      debArm64: `${github}/download/xguard-client_arm64.deb`,
      rpmX86_64: `${github}/download/xguard-client.x86_64.rpm`,
      rpmAarch64: `${github}/download/xguard-client.aarch64.rpm`,
      windowsX64: `${github}/download/xguard-client_x64.msi`,
      // No signed macOS build by default: the button opens the releases page.
      macosUniversal: github,
      releases: github,
    });
    expect(buildClientDownloadLinks(null)).toEqual(links);
  });

  it('appends the version-less asset names to a self-hosted base URL', () => {
    const links = buildClientDownloadLinks({
      base_url: 'https://mirror.example.lan/xguard/',
      releases_url: 'https://mirror.example.lan/xguard/',
      macos_installer: true,
      android_url: 'https://mirror.example.lan/xguard/xguard.apk',
      ios_url: '',
    });
    expect(links.windowsX64).toBe(
      'https://mirror.example.lan/xguard/xguard-client_x64.msi',
    );
    expect(links.macosUniversal).toBe(
      'https://mirror.example.lan/xguard/xguard-client_universal.dmg',
    );
    expect(links.rpmAarch64).toBe(
      'https://mirror.example.lan/xguard/xguard-client.aarch64.rpm',
    );
    expect(links.android).toBe('https://mirror.example.lan/xguard/xguard.apk');
    expect(links.ios).toBeUndefined();
  });

  it('never renders non-http links, whatever the server sent', () => {
    const links = buildClientDownloadLinks({
      base_url: 'javascript:alert(1)',
      releases_url: 'not a url',
      android_url: 'intent://evil',
      ios_url: 'https://apps.apple.com/app/id1',
    });
    expect(links.windowsX64).toBe(`${github}/download/xguard-client_x64.msi`);
    expect(links.releases).toBe(github);
    expect(links.android).toBeUndefined();
    expect(links.ios).toBe('https://apps.apple.com/app/id1');
  });

  it('lists the menu entries', () => {
    const links = buildClientDownloadLinks();
    expect(linuxDownloadItems(links).map((item) => item.href)).toEqual([
      links.debAmd64,
      links.debArm64,
      links.rpmX86_64,
      links.rpmAarch64,
    ]);
    expect(mobileDownloadItems(links)).toEqual([]);
    expect(
      mobileDownloadItems({ ...links, android: 'https://a.example/x.apk' }).map(
        (i) => i.id,
      ),
    ).toEqual(['android']);
  });

  it('builds asset URLs without double slashes', () => {
    expect(assetUrl('https://a.example/x//', 'f.msi')).toBe('https://a.example/x/f.msi');
    expect(Object.values(clientAssetNames)).toHaveLength(6);
  });
});

describe('checkClientDownloadUrl', () => {
  const base = { allowHttp: false, pathOnly: true };
  it('accepts https and refuses http without the opt-in', () => {
    expect(checkClientDownloadUrl('https://a.example/x', base)).toEqual({
      ok: true,
      insecure: false,
    });
    expect(checkClientDownloadUrl('http://10.0.0.5/x', base)).toEqual({ ok: false });
    expect(
      checkClientDownloadUrl('http://10.0.0.5/x', { ...base, allowHttp: true }),
    ).toEqual({ ok: true, insecure: true });
  });

  it('refuses credentials, other schemes and, for the base URL, queries', () => {
    expect(checkClientDownloadUrl('https://u:p@a.example/x', base).ok).toBe(false);
    expect(checkClientDownloadUrl('ftp://a.example/x', base).ok).toBe(false);
    expect(checkClientDownloadUrl('javascript:alert(1)', base).ok).toBe(false);
    expect(checkClientDownloadUrl('https://a.example/x?v=1', base).ok).toBe(false);
    expect(
      checkClientDownloadUrl('https://a.example/x?id=1', { ...base, pathOnly: false }).ok,
    ).toBe(true);
  });

  it('validates the settings form', () => {
    const valid: ClientDownloadSettings = { ...defaultClientDownloadSettings };
    expect(validateClientDownloadForm(valid)).toEqual({ errors: {}, insecure: false });
    const result = validateClientDownloadForm({
      ...valid,
      base_url: 'http://mirror.lan/x',
      releases_url: '',
      ios_url: 'itms-apps://x',
    });
    expect(Object.keys(result.errors).sort()).toEqual([
      'base_url',
      'ios_url',
      'releases_url',
    ]);
    expect(
      validateClientDownloadForm({
        ...valid,
        base_url: 'http://mirror.lan/x',
        allow_http: true,
      }),
    ).toEqual({ errors: {}, insecure: true });
  });
});

describe('content fetches', () => {
  it('fetches no contextual help or video tutorials without a configured source', () => {
    expect(contextualHelpQueryOptions.enabled).toBe(false);
    expect(videoTutorialsQueryOptions.enabled).toBe(false);
  });
});

describe('AddDeviceModalClientConfigStep', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    useAddUserDeviceModal.setState({ enrollment: undefined });
  });

  const renderStep = (settings: ClientDownloadSettings) => {
    const response: ClientDownloadsResponse = {
      ...settings,
      asset_names: Object.values(clientAssetNames),
      defaults: {
        base_url: defaultClientDownloadSettings.base_url,
        releases_url: defaultClientDownloadSettings.releases_url,
      },
    };
    vi.spyOn(api.clientDownloads, 'get').mockResolvedValue({
      data: response,
    } as AxiosResponse<ClientDownloadsResponse>);
    useAddUserDeviceModal.setState({
      enrollment: { token: 'token', url: 'https://edge.example.com' },
    });
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <AddDeviceModalClientConfigStep />
      </QueryClientProvider>,
    );
  };

  it('links the installers from the configured server and hides missing mobile apps', async () => {
    renderStep({
      ...defaultClientDownloadSettings,
      base_url: 'https://mirror.example.lan/xguard',
      macos_installer: true,
    });
    await waitFor(() =>
      expect(screen.getByTestId('download-windows')).toHaveAttribute(
        'href',
        'https://mirror.example.lan/xguard/xguard-client_x64.msi',
      ),
    );
    expect(screen.getByTestId('download-macos')).toHaveAttribute(
      'href',
      'https://mirror.example.lan/xguard/xguard-client_universal.dmg',
    );
    expect(screen.queryByTestId('download-android')).toBeNull();
    expect(screen.queryByTestId('download-ios')).toBeNull();
    expect(document.body.innerHTML).not.toContain('play.google.com');
    expect(document.body.innerHTML).not.toContain('apps.apple.com');
  });

  it('shows the mobile links that are set', async () => {
    renderStep({
      ...defaultClientDownloadSettings,
      ios_url: 'https://apps.apple.com/app/id123',
    });
    await waitFor(() =>
      expect(screen.getByTestId('download-ios')).toHaveAttribute(
        'href',
        'https://apps.apple.com/app/id123',
      ),
    );
    expect(screen.queryByTestId('download-android')).toBeNull();
    expect(screen.getByTestId('download-macos')).toHaveAttribute('href', github);
  });
});
