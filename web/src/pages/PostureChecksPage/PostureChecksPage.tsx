import './style.scss';
import { useSuspenseQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { m } from '../../paraglide/messages';
import { LocationServiceMode } from '../../shared/api/types';
import { Page } from '../../shared/components/Page/Page';
import { TablePageLayout } from '../../shared/layout/TablePageLayout/TablePageLayout';
import {
  getDevicePosturesQueryOptions,
  getDevicePostureVersionsQueryOptions,
  getLocationsQueryOptions,
} from '../../shared/query';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { CEPostureCheckModal } from './modals/CEPostureCheckModal/CEPostureCheckModal';
import { PostureChecksTable } from './PostureChecksTable';

export const PostureChecksPage = () => {
  const { data: postures } = useSuspenseQuery(getDevicePosturesQueryOptions);
  const { data: versions } = useSuspenseQuery(getDevicePostureVersionsQueryOptions);
  const { data: locations } = useSuspenseQuery(getLocationsQueryOptions);

  const locationNames = useMemo(
    () => new Map(locations.map((location) => [location.id, location.name])),
    [locations],
  );
  const locationOptions = useMemo(
    () =>
      locations
        .filter(
          (location) => location.service_location_mode === LocationServiceMode.Disabled,
        )
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((location) => ({ id: location.id, label: location.name })),
    [locations],
  );

  return (
    <>
      <Page id="posture-checks-page" title={m.posture_checks_page_title()}>
        <SizedBox height={ThemeSpacing.Xl2} />
        <TablePageLayout>
          <p className="posture-checks-description">
            {m.posture_checks_page_description()}
          </p>
          <SizedBox height={ThemeSpacing.Xl} />
          <PostureChecksTable postures={postures} locationNames={locationNames} />
        </TablePageLayout>
      </Page>
      <CEPostureCheckModal locations={locationOptions} versions={versions} />
    </>
  );
};
