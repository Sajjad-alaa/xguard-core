import { Link } from '@tanstack/react-router';
import { m } from '../../../../paraglide/messages';
import {
  ContextualHelpKey,
  ContextualHelpSidebar,
} from '../../../../shared/components/ContextualHelp';
import { SettingsLayout } from '../../../../shared/components/SettingsLayout/SettingsLayout';
import { useApp } from '../../../../shared/hooks/useApp';
import { SectionSelect } from '../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { getConfiguredBadge, getNotConfiguredBadge } from '../types';

export const SettingsNotificationsTab = () => {
  const smtp = useApp((s) => s.appInfo.smtp_enabled);

  return (
    <SettingsLayout
      suggestion={
        <ContextualHelpSidebar pageKey={ContextualHelpKey.SettingsNotifications} />
      }
    >
      <Link to="/settings/smtp">
        <SectionSelect
          image="smtp"
          title={m.settings_smtp_title()}
          content={m.settings_notifications_smtp_card_content()}
          badgeProps={smtp ? getConfiguredBadge() : getNotConfiguredBadge()}
        />
      </Link>
      <SizedBox height={ThemeSpacing.Xl} />
      <Link to="/settings/gateway-notifications">
        <SectionSelect
          image="gateway-notifications"
          title={m.settings_gateway_notifications_title()}
          content={m.settings_notifications_gateway_card_content()}
        />
      </Link>
    </SettingsLayout>
  );
};
