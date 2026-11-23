import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Suspense } from 'react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { OpenIdClientTable } from '../src/pages/OpenIdPage/OpenIdTable';
import type { OpenIdClient } from '../src/shared/api/types';
import { getOpenIdClientQueryOptions } from '../src/shared/query';

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

const makeClient = (overrides: Partial<OpenIdClient> = {}): OpenIdClient => ({
  client_id: 'client-alpha',
  client_secret: 'secret-alpha',
  name: 'Alpha App',
  redirect_uri: ['https://alpha.example.com/cb'],
  scope: ['openid', 'profile'],
  enabled: true,
  ...overrides,
});

const renderTable = (clients: OpenIdClient[]) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(getOpenIdClientQueryOptions.queryKey, clients);
  return render(
    <QueryClientProvider client={client}>
      <Suspense fallback={null}>
        <OpenIdClientTable />
      </Suspense>
    </QueryClientProvider>,
  );
};

describe('OpenIdClientTable', () => {
  it('renders empty state when there are no OpenID applications', () => {
    renderTable([]);
    expect(
      screen.getByText("You don't have any OpenID applications."),
    ).toBeInTheDocument();
  });

  it('shows client ID badges and filters by name or client ID', async () => {
    renderTable([
      makeClient({ name: 'Grafana', client_id: 'grafana-id', enabled: true }),
      makeClient({ name: 'GitLab', client_id: 'gitlab-id', enabled: false }),
    ]);

    expect(screen.getByText('Grafana')).toBeInTheDocument();
    expect(screen.getByText('grafana-id')).toBeInTheDocument();
    expect(screen.getByText('GitLab')).toBeInTheDocument();
    expect(screen.getByText('gitlab-id')).toBeInTheDocument();

    const search = screen.getByPlaceholderText(/Search applications/i);
    fireEvent.change(search, { target: { value: 'gitlab-id' } });

    await waitFor(() => {
      expect(screen.queryByText('Grafana')).not.toBeInTheDocument();
    });
    expect(screen.getByText('GitLab')).toBeInTheDocument();
  });
});
