import { m } from '../../../../../paraglide/messages';
import { LayoutGrid } from '../../../../../shared/components/LayoutGrid/LayoutGrid';
import { openModal } from '../../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../../shared/hooks/modalControls/modalTypes';
import { Button } from '../../../../../shared/xguard-ui/components/Button/Button';
import { EmptyStateFlexible } from '../../../../../shared/xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import { ProfileTabHeader } from '../../components/ProfileTabHeader/ProfileTabHeader';
import { useUserProfile } from '../../hooks/useUserProfilePage';
import { ApiTokensTabAvailability, type ApiTokensTabAvailabilityValue } from '../types';
import { ProfileApiTokensTable } from './components/ProfileApiTokensTable/ProfileApiTokensTable';
import { AddApiTokenModal } from './modals/AddApiTokenModal/AddApiTokenModal';
import { RenameApiTokenModal } from './modals/RenameApiTokenModal/RenameApiTokenModal';

type Props = {
  availability: ApiTokensTabAvailabilityValue;
  isLoading: boolean;
  /** Tokens can only be created by their owner. */
  isSelf: boolean;
};

export const ProfileApiTokensTab = ({ availability, isLoading, isSelf }: Props) => {
  if (availability === ApiTokensTabAvailability.Hidden) {
    return null;
  }

  if (isLoading) {
    return (
      <EmptyStateFlexible icon="api-token" title={m.profile_api_tokens_loading_title()} />
    );
  }

  return <AvailableProfileApiTokensTab isSelf={isSelf} />;
};

const AvailableProfileApiTokensTab = ({ isSelf }: { isSelf: boolean }) => {
  const username = useUserProfile((s) => s.user.username);
  const isUserActive = useUserProfile((s) => s.user.is_active);
  const apiTokens = useUserProfile((s) => s.apiTokens);

  const handleAddApiToken = () => {
    if (!isUserActive) {
      Snackbar.error(m.modal_add_api_token_disabled_user_error());
      return;
    }
    openModal(ModalName.AddApiToken, { username });
  };

  return (
    <>
      {apiTokens.length === 0 &&
        (isSelf ? (
          <EmptyStateFlexible
            icon="api-token"
            title={m.profile_api_tokens_empty_title()}
            subtitle={m.profile_api_tokens_empty_subtitle()}
            primaryAction={{
              iconLeft: 'add-token',
              testId: 'add-token',
              text: m.profile_api_tokens_add(),
              onClick: handleAddApiToken,
            }}
          />
        ) : (
          <EmptyStateFlexible
            icon="api-token"
            title={m.profile_api_tokens_empty_other_title()}
            subtitle={m.profile_api_tokens_other_note()}
          />
        ))}
      {apiTokens.length > 0 && (
        <LayoutGrid>
          <SizedBox height={ThemeSpacing.Xl3} />
          <ProfileTabHeader title={m.profile_api_tokens_title()}>
            {isSelf && (
              <Button
                text={m.profile_api_tokens_add()}
                iconLeft="add-token"
                testId="add-token"
                onClick={handleAddApiToken}
              />
            )}
          </ProfileTabHeader>
          {!isSelf && (
            <p className="api-tokens-note">{m.profile_api_tokens_other_note()}</p>
          )}
          <ProfileApiTokensTable />
        </LayoutGrid>
      )}
      {isSelf && <AddApiTokenModal />}
      <RenameApiTokenModal />
    </>
  );
};
