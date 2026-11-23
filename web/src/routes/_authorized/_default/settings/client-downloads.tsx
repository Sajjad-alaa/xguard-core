import { createFileRoute } from '@tanstack/react-router';
import { SettingsClientDownloadsPage } from '../../../../pages/settings/SettingsClientDownloadsPage/SettingsClientDownloadsPage';

export const Route = createFileRoute('/_authorized/_default/settings/client-downloads')({
  component: SettingsClientDownloadsPage,
});
