import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { FirewallRulesTable } from '../src/pages/FirewallPage/FirewallRulesTable';
import { emptyForm, formToInput } from '../src/pages/FirewallPage/rule/form';
import type { FirewallNames } from '../src/pages/FirewallPage/useFirewallNames';
import type { LocationPolicies } from '../src/pages/FirewallPage/useLocationPolicies';
import type { FirewallRule } from '../src/shared/api/types';
import { TableBadgesCell } from '../src/shared/components/TableBadgesCell/TableBadgesCell';

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

const mockNavigate = vi.fn();
vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const names: FirewallNames = {
  locations: [{ id: 1, label: 'Office' }],
  users: [{ id: 1, label: 'Alice (alice)' }],
  groups: [{ id: 2, label: 'Engineering' }],
  devices: [],
};

const makeRule = (overrides: Partial<FirewallRule> = {}): FirewallRule => ({
  ...formToInput(
    {
      ...emptyForm(),
      name: 'Allow HTTPS',
      description: 'Internal web apps',
      users: [1],
      destinations: '10.0.0.0/24',
      protocols: new Set([6]),
      ports: '443',
      all_locations: false,
      locations: [1],
    },
    null,
  ),
  id: 10,
  created_at: '2026-11-16T00:00:00',
  updated_at: '2026-11-16T00:00:00',
  ...overrides,
});

const emptyPolicies: LocationPolicies = {
  byLocation: new Map(),
  ruleLocations: new Map(),
  loading: false,
  error: false,
};

const renderWithQuery = (ui: React.ReactElement) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
};

describe('TableBadgesCell', () => {
  it('shows items up to limit and collapses overflow into a +N button', () => {
    render(
      <TableBadgesCell
        limit={2}
        items={[
          { key: 'a', label: 'Alpha' },
          { key: 'b', label: 'Beta' },
          { key: 'c', label: 'Gamma' },
        ]}
      />,
    );
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Beta')).toBeInTheDocument();
    expect(screen.queryByText('Gamma')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Show all 3/i })).toBeInTheDocument();
  });

  it('shows empty text when list is empty', () => {
    render(<TableBadgesCell items={[]} emptyText="None" />);
    expect(screen.getByText('None')).toBeInTheDocument();
  });
});

describe('FirewallRulesTable', () => {
  it('renders empty state when there are no rules', () => {
    renderWithQuery(
      <FirewallRulesTable rules={[]} names={names} policies={emptyPolicies} />,
    );
    expect(screen.getByText('No firewall rules yet.')).toBeInTheDocument();
    expect(screen.getByTestId('add-firewall-rule')).toBeInTheDocument();
  });

  it('renders rule badges, enforcement status, and filters by search query', async () => {
    const policies: LocationPolicies = {
      byLocation: new Map(),
      ruleLocations: new Map([[10, [1]]]),
      loading: false,
      error: false,
    };
    const rules = [
      makeRule({ id: 10, name: 'Allow HTTPS', ports: ['443'] }),
      makeRule({
        id: 11,
        name: 'Block SSH',
        action: 'deny',
        ports: ['22'],
        destinations: ['192.168.1.0/24'],
      }),
    ];

    renderWithQuery(
      <FirewallRulesTable rules={rules} names={names} policies={policies} />,
    );

    expect(screen.getByText('Allow HTTPS')).toBeInTheDocument();
    expect(screen.getByText('Block SSH')).toBeInTheDocument();
    expect(screen.getByText('Active in 1')).toBeInTheDocument();
    expect(screen.getByText('Not enforced')).toBeInTheDocument();

    const search = screen.getByPlaceholderText(/Search rules/i);
    fireEvent.change(search, { target: { value: '192.168.1.0/24' } });

    await waitFor(() => {
      expect(screen.queryByText('Allow HTTPS')).not.toBeInTheDocument();
    });
    expect(screen.getByText('Block SSH')).toBeInTheDocument();

    fireEvent.change(search, { target: { value: 'nonexistent-rule' } });
    await waitFor(() => {
      expect(screen.queryByText('Block SSH')).not.toBeInTheDocument();
    });
  });
});
