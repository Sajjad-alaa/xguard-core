import { Link } from '@tanstack/react-router';
import { m } from '../../../../paraglide/messages';
import {
  ContextualHelpKey,
  ContextualHelpSidebar,
} from '../../../../shared/components/ContextualHelp';
import { SettingsLayout } from '../../../../shared/components/SettingsLayout/SettingsLayout';
import { SectionSelect } from '../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';

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
    </SettingsLayout>
  );
};
