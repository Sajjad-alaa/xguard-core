import { Suspense } from 'react';
import { m } from '../../paraglide/messages';
import { Page } from '../../shared/components/Page/Page';
import { TableSkeleton } from '../../shared/components/skeleton/TableSkeleton/TableSkeleton';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { CeOpenIdClientModal } from './modals/CEOpenIdClientModal/CEOpenIdClientModal';
import { OpenIdClientTable } from './OpenIdTable';

export const OpenIdPage = () => {
  return (
    <>
      <Page title={m.openid_title()} id="openid-page">
        <SizedBox height={ThemeSpacing.Xl3} />
        <Suspense fallback={<TableSkeleton />}>
          <OpenIdClientTable />
        </Suspense>
      </Page>
      <CeOpenIdClientModal />
    </>
  );
};
