import { type QueryKey, queryOptions } from '@tanstack/react-query';
import axios from 'axios';
import api from './api/api';
import type { UserProfile } from './api/types';
import { buildClientDownloadLinks } from './clientDownloads';
import {
  contextualHelpSource,
  parseContextualHelp,
} from './components/ContextualHelp/data';
import { resourceDisplayMap } from './utils/resourceById';
import { parseVideoTutorials, videoTutorialsSource } from './video-tutorials/data';

export const getLocationsCountQueryOptions = queryOptions({
  queryFn: api.location.getCount,
  queryKey: ['network', 'count'],
  select: (resp) => resp.data.count,
});

export const getLocationQueryOptions = (id: number) =>
  queryOptions({
    queryFn: () => api.location.getLocation(id),
    queryKey: ['network', id],
    select: (resp) => resp.data,
  });

export const getLocationsQueryOptions = queryOptions({
  queryFn: api.location.getLocations,
  queryKey: ['network'],
  select: (resp) => resp.data,
});

export const getLocationsDisplayQueryOptions = queryOptions({
  queryFn: api.location.getLocationsDisplay,
  queryKey: ['network', 'display', 'resourceMap'],
  select: (resp) => resourceDisplayMap(resp.data),
});

export const getMfaFlowsQueryOptions = queryOptions({
  queryFn: api.mfaFlow.list,
  queryKey: ['mfa-flow'],
  select: (response) => response.data,
});

export const getLocationMfaFlowsQueryOptions = (locationId: number) =>
  queryOptions({
    queryFn: () => api.mfaFlow.getLocationAssignments(locationId),
    queryKey: ['location', locationId, 'mfa-flows'],
    select: (response) => response.data,
  });

export const mfaAvailabilityInvalidateKey: QueryKey = ['mfa-flow'];

export const getMfaMethodAvailabilityQueryOptions = queryOptions({
  queryFn: api.mfaFlow.methodAvailability,
  queryKey: ['mfa-flow', 'method-availability'],
  select: (response) => ({
    methodAvailability: response.data,
    methods: response.data.map(({ method }) => method),
  }),
});

export const getEdgesQueryOptions = queryOptions({
  queryFn: api.edge.getEdges,
  queryKey: ['edge'],
  select: (resp) => resp.data,
  refetchOnReconnect: true,
});

export const getGatewaysQueryOptions = queryOptions({
  queryFn: api.gateway.getGateways,
  queryKey: ['gateway'],
  select: (resp) => resp.data,
  refetchInterval: 30_000,
  refetchOnReconnect: true,
});

export const getEdgeQueryOptions = (id: number) =>
  queryOptions({
    queryFn: () => api.edge.getEdge(id),
    queryKey: ['edge', id],
    select: (resp) => resp.data,
  });

export const getGatewayQueryOptions = (id: number) =>
  queryOptions({
    queryFn: () => api.gateway.getGateway(id),
    queryKey: ['gateway', id],
    select: (resp) => resp.data,
  });

export const getNetworkDevicesQueryOptions = queryOptions({
  queryFn: api.network_device.getDevices,
  queryKey: ['device', 'network'],
});

export const getUserMeQueryOptions = queryOptions({
  queryFn: api.user.getMe,
  queryKey: ['me'],
  staleTime: 60_000,
  throwOnError: false,
  retry: false,
  refetchOnWindowFocus: false,
  refetchOnReconnect: true,
});

export const userProfileQueryOptions = (username: string) =>
  queryOptions({
    queryFn: () => api.user.getUser(username),
    select: ({ data }) => {
      const res: UserProfile = {
        devices: data.user.devices.map((device) => ({
          ...device,
          biometry_enabled: data.biometric_enabled_devices.includes(device.id),
        })),
        security_keys: data.security_keys,
        user: data.user,
      };
      return res;
    },
    queryKey: ['user', username],
    refetchOnReconnect: true,
  });

/** Client download links; falls back to the built-in defaults when the request fails. */
export const clientDownloadsQueryOptions = queryOptions({
  queryKey: ['client_downloads', 'links'],
  queryFn: () =>
    api.clientDownloads
      .get()
      .then((resp) => resp.data)
      .catch(() => null),
  select: (data) => buildClientDownloadLinks(data),
  staleTime: 180 * 1000,
  refetchOnWindowFocus: false,
});

export const getClientDownloadSettingsQueryOptions = queryOptions({
  queryKey: ['client_downloads'],
  queryFn: () => api.clientDownloads.get().then((resp) => resp.data),
});

export const videoTutorialsQueryOptions = queryOptions({
  queryKey: ['content', 'video-tutorials'],
  // No public source exists for XGuard yet: without VITE_VIDEO_TUTORIALS_URL nothing is fetched
  // and every video tutorial entry point stays hidden.
  enabled: videoTutorialsSource !== undefined,
  queryFn: () => axios.get<unknown>(videoTutorialsSource ?? ''),
  select: (resp) => {
    try {
      return parseVideoTutorials(resp.data);
    } catch (err) {
      console.error(
        '[video-tutorials] Fetched successfully but failed to parse response:',
        err,
      );
      throw err;
    }
  },
  // Mappings are version-tied and won't meaningfully change within a session.
  staleTime: Infinity,
  // Silent failure: if the fetch or parse fails, the widget simply won't appear.
  retry: false,
});

export const contextualHelpQueryOptions = queryOptions({
  queryKey: ['content', 'contextual-help'],
  // Same as the video tutorials: disabled unless VITE_CONTEXTUAL_HELP_URL is set at build time.
  enabled: contextualHelpSource !== undefined,
  queryFn: () => axios.get<unknown>(contextualHelpSource ?? ''),
  select: (resp) => {
    try {
      return parseContextualHelp(resp.data);
    } catch (err) {
      console.error(
        '[contextual-help] Fetched successfully but failed to parse response:',
        err,
      );
      throw err;
    }
  },
  staleTime: Infinity,
  retry: false,
});

export const getActivityLogStreamsQueryOptions = queryOptions({
  queryFn: api.activityLogStream.getStreams,
  queryKey: ['activity_log_stream'],
  select: (resp) => resp.data,
  // Delivery status changes on its own.
  refetchInterval: 10_000,
});

export const getUserApiTokensQueryOptions = (username: string, enabled: boolean) =>
  queryOptions({
    queryFn: () => api.user.getApiTokens(username),
    queryKey: ['user', username, 'api_token'],
    select: (response) => response.data,
    refetchOnReconnect: true,
    throwOnError: false,
    enabled,
  });

export const getUserAuthKeysQueryOptions = (username: string) =>
  queryOptions({
    queryFn: () => api.user.getAuthKeys(username),
    queryKey: ['user', username, 'auth_key'],
    select: (response) => response.data,
    refetchOnReconnect: true,
  });

export const getUsersQueryOptions = queryOptions({
  queryFn: api.user.getAllUsers,
  queryKey: ['user'],
  refetchOnReconnect: true,
});

export const getUsersOverviewQueryOptions = queryOptions({
  queryFn: api.user.getAllUsers,
  queryKey: ['user', 'all'],
  refetchOnReconnect: true,
});

export const getGroupsInfoQueryOptions = queryOptions({
  queryFn: api.group.getGroupsInfo,
  queryKey: ['group-info'],
  select: (resp) => resp.data,
  refetchOnReconnect: true,
});

export const getOpenIdClientQueryOptions = queryOptions({
  queryFn: api.openIdClient.getOpenIdClients,
  queryKey: ['oauth'],
});

export const getDevicePosturesQueryOptions = queryOptions({
  queryFn: api.devicePosture.getDevicePostures,
  queryKey: ['device-posture'],
  select: (resp) => resp.data,
});

export const getDevicePostureVersionsQueryOptions = queryOptions({
  queryFn: api.devicePosture.getVersionCatalog,
  queryKey: ['device-posture', 'versions'],
  select: (resp) => resp.data,
  staleTime: Infinity,
});

export const getDevicePostureSnapshotQueryOptions = (deviceId: number) =>
  queryOptions({
    queryFn: () => api.devicePosture.getDeviceSnapshot(deviceId),
    queryKey: ['device-posture', 'device', deviceId],
    select: (resp) => resp.data,
  });

export const getFirewallRulesQueryOptions = queryOptions({
  queryFn: api.firewall.getRules,
  queryKey: ['firewall', 'rule'],
  select: (resp) => resp.data,
});

export const getFirewallLocationPolicyQueryOptions = (locationId: number) =>
  queryOptions({
    queryFn: () => api.firewall.getLocationPolicy(locationId),
    queryKey: ['firewall', 'policy', locationId],
    select: (resp) => resp.data,
  });

export const getSnatBindingsQueryOptions = queryOptions({
  queryFn: api.firewall.getSnatBindings,
  queryKey: ['firewall', 'snat'],
  select: (resp) => resp.data,
});

export const getWebhooksQueryOptions = queryOptions({
  queryFn: api.webhook.getWebhooks,
  queryKey: ['webhook'],
  select: (resp) => resp.data,
});

export const getSettingsQueryOptions = queryOptions({
  queryFn: api.settings.getSettings,
  queryKey: ['settings'],
  select: (resp) => resp.data,
});

export const getClientSettingsQueryOptions = queryOptions({
  queryFn: api.settings.getClientSettings,
  queryKey: ['client_settings'],
  select: (resp) => resp.data,
});

export const getActivityLogEventQueryOptions = (id: number) =>
  queryOptions({
    queryFn: () => api.getActivityLogEvent(id).then((resp) => resp.data),
    queryKey: ['activity-log-event', id],
    staleTime: Infinity,
  });

export const getLicenseInfoQueryOptions = queryOptions({
  queryFn: api.getLicenseInfo,
  queryKey: ['enterprise_info'],
});

export const getSessionInfoQueryOptions = queryOptions({
  queryFn: api.getSessionInfo,
  queryKey: ['session-info'],
  select: (resp) => resp.data,
  refetchOnReconnect: true,
  refetchOnWindowFocus: false,
});

export const getVersionQueryOptions = queryOptions({
  queryFn: api.app.version,
  queryKey: ['version'],
  select: (resp) => resp.data.version,
  refetchOnReconnect: true,
  refetchOnWindowFocus: false,
});

export const getSettingsEssentialsQueryOptions = queryOptions({
  queryFn: api.settings.getSettingsEssentials,
  queryKey: ['settings_essentials'],
  retry: false,
  refetchOnWindowFocus: false,
  refetchOnReconnect: true,
  staleTime: 60_000,
  select: (resp) => resp.data,
});

export const getInitialSetupCaQueryOptions = queryOptions({
  queryFn: api.initial_setup.getCA,
  queryKey: ['initial_setup', 'ca'],
  select: (resp) => resp.data,
});

export const getMigrationCaQueryOptions = queryOptions({
  queryFn: api.migration.ca.getCA,
  queryKey: ['migration', 'ca'],
  select: (resp) => resp.data,
});

export const getMigrationStateQueryOptions = queryOptions({
  queryFn: api.migration.state.getMigrationState,
  queryKey: ['migration', 'state'],
  select: (resp) => resp.data,
});
