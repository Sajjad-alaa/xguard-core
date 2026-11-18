import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AddLocationModalContent } from '../src/pages/LocationsPage/modals/AddLocationModal/AddLocationModal';

// useNavigate would otherwise require a RouterProvider; the gating logic under test doesn't.
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  useNavigate: () => vi.fn(),
}));

describe('AddLocationModalContent service-location option', () => {
  const getServiceOption = () => screen.getByTestId('add-service-location');

  it('is available: XGuard clients run service locations', () => {
    render(<AddLocationModalContent modalData={{ license: null }} />);

    expect(getServiceOption()).not.toHaveClass('disabled');
  });

  it('does not advertise a paid tier', () => {
    render(<AddLocationModalContent modalData={{ license: null }} />);

    expect(getServiceOption()).not.toHaveTextContent('Enterprise');
    expect(getServiceOption()).not.toHaveTextContent('Business');
  });
});
