import { Link } from '@tanstack/react-router';
import { m } from '../../../../paraglide/messages';
import {
  ContextualHelpKey,
  ContextualHelpSidebar,
} from '../../../../shared/components/ContextualHelp';
import { SettingsLayout } from '../../../../shared/components/SettingsLayout/SettingsLayout';
import { SectionSelect } from '../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';

export const SettingsExternalProvidersTab = () => (
  <SettingsLayout
    suggestion={<ContextualHelpSidebar pageKey={ContextualHelpKey.SettingsIdentity} />}
  >
    <Link to="/settings/openid">
      <SectionSelect
        image="external-id"
        title={m.settings_openid_page_title()}
        content={m.settings_openid_page_subtitle()}
      />
    </Link>
    <SizedBox height={ThemeSpacing.Xl} />
    <Link to="/settings/ldap">
      <SectionSelect
        image="ldap"
        title={m.settings_ldap_title()}
        content={m.settings_ldap_subtitle()}
      />
    </Link>
  </SettingsLayout>
);
