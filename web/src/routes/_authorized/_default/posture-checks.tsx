import { createFileRoute } from '@tanstack/react-router';
import { PostureChecksPage } from '../../../pages/PostureChecksPage/PostureChecksPage';
import {
  getDevicePosturesQueryOptions,
  getDevicePostureVersionsQueryOptions,
  getLocationsQueryOptions,
} from '../../../shared/query';

export const Route = createFileRoute('/_authorized/_default/posture-checks')({
  component: PostureChecksPage,
  loader: ({ context }) =>
    Promise.all([
      context.queryClient.fetchQuery(getDevicePosturesQueryOptions),
      context.queryClient.fetchQuery(getDevicePostureVersionsQueryOptions),
      context.queryClient.fetchQuery(getLocationsQueryOptions),
    ]),
});
