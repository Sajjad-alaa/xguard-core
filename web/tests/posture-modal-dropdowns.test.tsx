import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { CEPostureCheckModal } from '../src/pages/PostureChecksPage/modals/CEPostureCheckModal/CEPostureCheckModal';
import type {
  ApiDevicePosture,
  DevicePostureVersionCatalog,
} from '../src/shared/api/types';
import { openModal } from '../src/shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../src/shared/hooks/modalControls/modalTypes';

// The design system looks up the app root and the modal portal target when it loads.
vi.hoisted(() => {
  for (const id of ['root', 'modals-root', 'snackbar-root']) {
    const element = document.createElement('div');
    element.id = id;
    document.body.appendChild(element);
  }
});

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') {
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
});

const versions: DevicePostureVersionCatalog = {
  windows: [{ value: '10.0.26100', label: 'Windows 11 24H2' }],
  macos: [{ value: '15', label: 'macOS 15 Sequoia' }],
  ios: [{ value: '18', label: 'iOS 18' }],
  android: [{ value: '15', label: 'Android 15' }],
  linux_kernel: [{ value: '6.6', label: '6.6 LTS' }],
  desktop_client: [{ value: '2.3.1', label: '2.3.1' }],
  mobile_client: [{ value: '2.3.1', label: '2.3.1' }],
};

const posture: ApiDevicePosture = {
  id: 4,
  name: 'Macs',
  description: null,
  min_desktop_client_version: '2.3.1',
  min_mobile_client_version: null,
  allow_prerelease_client: false,
  locations: [],
  os_rules: [
    {
      os_type: 'macos',
      min_os_version: '14.6',
      disk_encryption_required: null,
      firewall_required: null,
      screen_lock_required: null,
      device_integrity_required: null,
      antivirus_required: true,
      ad_domain_joined_required: null,
      security_update_max_age: 30,
    },
  ],
};

const renderModal = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <CEPostureCheckModal locations={[]} versions={versions} />
    </QueryClientProvider>,
  );
};

describe('posture policy modal dropdowns', () => {
  it('shows catalog choices, a stored custom value and reveals the custom input', async () => {
    renderModal();
    await act(async () => {
      openModal(ModalName.CEPostureCheck, { posture });
    });

    // Catalog value: shown by its label, no custom input.
    expect(
      within(
        await screen.findByTestId('field-min_desktop_client_version_choice'),
      ).getByText('2.3.1'),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('field-min_desktop_client_version')).toBeNull();
    expect(
      within(screen.getByTestId('field-min_mobile_client_version_choice')).getByText(
        'Any version',
      ),
    ).toBeInTheDocument();

    // Stored version not in the catalog: Custom with the value filled in.
    expect(
      within(screen.getByTestId('field-macos_version_choice')).getByText('Custom…'),
    ).toBeInTheDocument();
    expect(screen.getByTestId('field-macos_version')).toHaveValue('14.6');
    expect(
      within(screen.getByTestId('field-macos_update_age_choice')).getByText('30 days'),
    ).toBeInTheDocument();
    expect(screen.getByText('Antivirus or EDR agent running')).toBeInTheDocument();

    // Picking Custom… reveals the input.
    fireEvent.click(screen.getByTestId('field-min_mobile_client_version_choice'));
    fireEvent.click(within(await screen.findByRole('list')).getByText('Custom…'));
    expect(
      await screen.findByTestId('field-min_mobile_client_version'),
    ).toBeInTheDocument();
  });
});
