import { createFileRoute } from '@tanstack/react-router';
import { SettingsRadiusPage } from '../../../../pages/settings/SettingsRadiusPage/SettingsRadiusPage';

export const Route = createFileRoute('/_authorized/_default/settings/radius')({
  component: SettingsRadiusPage,
});
