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

export const SettingsGeneralTab = () => {
  return (
    <SettingsLayout
      id="general-settings"
      suggestion={<ContextualHelpSidebar pageKey={ContextualHelpKey.SettingsGeneral} />}
    >
      <Link to="/settings/instance">
        <SectionSelect
          image="customization"
          title={m.settings_instance_title()}
          content={m.settings_general_section_instance_content()}
        />
      </Link>
      <SizedBox height={ThemeSpacing.Xl} />
      <Link to="/settings/client">
        <SectionSelect
          image="behavior"
          title={m.settings_breadcrumb_client_behavior()}
          content={m.settings_general_section_client_behavior_content()}
        />
      </Link>
    </SettingsLayout>
  );
};
