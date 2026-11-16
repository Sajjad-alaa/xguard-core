import type { QueryClient } from '@tanstack/react-query';
import { createRootRouteWithContext, Outlet } from '@tanstack/react-router';
import { AppLoaderPage } from '../pages/AppLoaderPage/AppLoaderPage';
import { AppSettingsEssentialsProvider } from '../shared/providers/AppSettingsEssentialsProvider';
import { SnackbarManager } from '../shared/xguard-ui/providers/snackbar/SnackbarManager';

interface RouterContext {
  queryClient: QueryClient;
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootComponent,
  pendingComponent: AppLoaderPage,
  pendingMs: 500,
  pendingMinMs: 250,
});

function RootComponent() {
  return (
    <SnackbarManager>
      <AppSettingsEssentialsProvider>
        <Outlet />
      </AppSettingsEssentialsProvider>
    </SnackbarManager>
  );
}
