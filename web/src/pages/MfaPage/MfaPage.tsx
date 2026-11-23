import { useSuspenseQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { Suspense } from 'react';
import { m } from '../../paraglide/messages';
import { DeletionBlockedModal } from '../../shared/components/modals/DeletionBlockedModal/DeletionBlockedModal';
import { Page } from '../../shared/components/Page/Page';
import { TableSkeleton } from '../../shared/components/skeleton/TableSkeleton/TableSkeleton';
import { TablePageLayout } from '../../shared/layout/TablePageLayout/TablePageLayout';
import { getMfaFlowsQueryOptions } from '../../shared/query';
import type { ButtonProps } from '../../shared/xguard-ui/components/Button/types';
import { EmptyStateFlexible } from '../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { MfaFlowsTable } from './MfaFlowsTable';

const MfaPageContent = () => {
  const navigate = useNavigate();
  const { data: flows } = useSuspenseQuery(getMfaFlowsQueryOptions);
  const addMfaFlowButtonProps: ButtonProps = {
    text: m.mfa_flows_button_add(),
    iconLeft: 'plus',
    testId: 'add-mfa-flow',
    onClick: () => {
      void navigate({ to: '/mfa/add-flow' });
    },
  };

  return (
    <TablePageLayout>
      {flows.length > 0 ? (
        <MfaFlowsTable flows={flows} addButtonProps={addMfaFlowButtonProps} />
      ) : (
        <EmptyStateFlexible
          icon="posture-checks"
          title={m.mfa_flows_empty_title()}
          subtitle={m.mfa_flows_empty_subtitle()}
          primaryAction={addMfaFlowButtonProps}
        />
      )}
    </TablePageLayout>
  );
};

export const MfaPage = () => {
  return (
    <Page id="mfa-page" title={m.cmp_nav_item_mfa()}>
      <SizedBox height={ThemeSpacing.Xl3} />
      <Suspense fallback={<TableSkeleton />}>
        <MfaPageContent />
      </Suspense>
      <DeletionBlockedModal />
    </Page>
  );
};
