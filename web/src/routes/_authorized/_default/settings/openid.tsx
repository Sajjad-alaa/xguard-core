import { createFileRoute } from '@tanstack/react-router';
import { SettingsOpenIdPage } from '../../../../pages/settings/SettingsOpenIdPage/SettingsOpenIdPage';

export const Route = createFileRoute('/_authorized/_default/settings/openid')({
  component: SettingsOpenIdPage,
});
