import './style.scss';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { m } from '../../../paraglide/messages';
import {
  ContextualHelpKey,
  ContextualHelpSidebar,
} from '../../../shared/components/ContextualHelp';
import { SettingsHeader } from '../../../shared/components/SettingsHeader/SettingsHeader';
import { SettingsLayout } from '../../../shared/components/SettingsLayout/SettingsLayout';
import { openModal } from '../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../shared/hooks/modalControls/modalTypes';
import { getActivityLogStreamsQueryOptions } from '../../../shared/query';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import type { ButtonProps } from '../../../shared/xguard-ui/components/Button/types';
import { EmptyState } from '../../../shared/xguard-ui/components/EmptyState/EmptyState';
import { TableTop } from '../../../shared/xguard-ui/components/table/TableTop/TableTop';
import { ActivityLogStreamTable } from './ActivityLogStreamTable';
import { AddLogStreamingModal } from './modals/AddDestinationModal/AddLogStreamingModal';
import { EditLogStreamingModal } from './modals/EditDestinationModal/EditLogStreamingModal';

export const SettingsActivityLogStreamingPage = () => {
  const { data: streams } = useQuery(getActivityLogStreamsQueryOptions);

  const isEmpty = !streams || streams.length === 0;

  const addButtonProps = useMemo(
    (): ButtonProps => ({
      text: m.settings_activity_log_streaming_add_log_streaming_button(),
      iconLeft: 'file-add',
      testId: 'add-activity-stream',
      onClick: () => openModal(ModalName.AddLogStreaming),
    }),
    [],
  );

  return (
    <SettingsLayout
      id="settings-activity-log-streaming-tab"
      suggestion={<ContextualHelpSidebar pageKey={ContextualHelpKey.SettingsActivity} />}
    >
      <SettingsHeader
        icon="activity"
        title={m.settings_activity_log_streaming_title()}
        subtitle={m.settings_activity_log_streaming_description()}
      />
      {isEmpty ? (
        <EmptyState
          id="empty-state-upstreams"
          icon="log"
          title={m.settings_activity_log_streaming_no_upstreams()}
          subtitle={m.settings_activity_log_streaming_no_upstreams_subtitle()}
          primaryAction={addButtonProps}
        />
      ) : (
        <>
          <TableTop text={m.settings_activity_log_streaming_table_title()}>
            <Button {...addButtonProps} />
          </TableTop>
          <ActivityLogStreamTable data={streams} />
        </>
      )}
      <AddLogStreamingModal />
      <EditLogStreamingModal />
    </SettingsLayout>
  );
};
