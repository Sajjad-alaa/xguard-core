import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { PostureChecksTable } from '../src/pages/PostureChecksPage/PostureChecksTable';
import {
  clientItems,
  locationItems,
  postureSearchText,
  systemItems,
} from '../src/pages/PostureChecksPage/summary';
import type { ApiDevicePosture } from '../src/shared/api/types';

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') {
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
});

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({
    count,
    estimateSize,
  }: {
    count: number;
    estimateSize: () => number;
  }) => {
    const size = estimateSize();
    return {
      getTotalSize: () => count * size,
      getVirtualItems: () =>
        Array.from({ length: count }, (_, index) => ({
          index,
          key: index,
          start: index * size,
          size,
          end: (index + 1) * size,
        })),
      measureElement: () => {},
    };
  },
}));

const makePosture = (overrides: Partial<ApiDevicePosture> = {}): ApiDevicePosture => ({
  id: 1,
  name: 'Corporate Laptops',
  description: 'Encrypted laptops only',
  min_desktop_client_version: '2.2.0',
  min_mobile_client_version: null,
  allow_prerelease_client: false,
  os_rules: [
    {
      os_type: 'windows',
      min_os_version: '10.0.22631',
      disk_encryption_required: true,
    },
    {
      os_type: 'macos',
      min_os_version: '14.5',
      disk_encryption_required: true,
    },
  ],
  locations: [1],
  ...overrides,
});

const renderWithQuery = (ui: React.ReactElement) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
};

describe('posture summary badge helpers', () => {
  it('builds system, client, location items and search text', () => {
    const p = makePosture({ allow_prerelease_client: true });
    const locations = new Map([[1, 'HQ']]);
    expect(systemItems(p).map((i) => i.label)).toEqual(['Windows', 'macOS']);
    expect(clientItems(p).map((i) => i.label)).toEqual(['Desktop 2.2.0', 'Pre-release']);
    expect(locationItems(p, locations).map((i) => i.label)).toEqual(['HQ']);
    const search = postureSearchText(p, locations);
    expect(search).toContain('corporate laptops');
    expect(search).toContain('windows');
    expect(search).toContain('hq');
  });

  it('handles empty OS rules and client versions gracefully', () => {
    const p = makePosture({
      os_rules: [],
      min_desktop_client_version: null,
      min_mobile_client_version: null,
      allow_prerelease_client: false,
      locations: [],
    });
    expect(systemItems(p).map((i) => i.label)).toEqual(['Any system']);
    expect(clientItems(p).map((i) => i.label)).toEqual(['Any version']);
    expect(locationItems(p, new Map())).toEqual([]);
  });
});

describe('PostureChecksTable', () => {
  it('renders empty state when there are no policies', () => {
    renderWithQuery(<PostureChecksTable postures={[]} locationNames={new Map()} />);
    expect(screen.getByText('No posture checks added yet.')).toBeInTheDocument();
    expect(screen.getByTestId('add-posture-check')).toBeInTheDocument();
  });

  it('renders badges and filters policies by search query', async () => {
    const locationNames = new Map([
      [1, 'Office'],
      [2, 'Cloud'],
    ]);
    const postures = [
      makePosture({ id: 1, name: 'Corporate Laptops', locations: [1] }),
      makePosture({
        id: 2,
        name: 'Mobile Only',
        description: 'iOS and Android devices',
        min_desktop_client_version: null,
        min_mobile_client_version: '2.1.0',
        os_rules: [{ os_type: 'ios', min_os_version: '17.0' }],
        locations: [2],
      }),
    ];

    renderWithQuery(
      <PostureChecksTable postures={postures} locationNames={locationNames} />,
    );

    expect(screen.getByText('Corporate Laptops')).toBeInTheDocument();
    expect(screen.getByText('Mobile Only')).toBeInTheDocument();
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('iOS')).toBeInTheDocument();
    expect(screen.getByText('Office')).toBeInTheDocument();

    const search = screen.getByPlaceholderText(/Search policies/i);
    fireEvent.change(search, { target: { value: 'Cloud' } });

    await waitFor(() => {
      expect(screen.queryByText('Corporate Laptops')).not.toBeInTheDocument();
    });
    expect(screen.getByText('Mobile Only')).toBeInTheDocument();
  });
});
