import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import {
  ContextualHelpKey,
  ContextualHelpSidebar,
} from '../../../../shared/components/ContextualHelp';
import { SettingsCard } from '../../../../shared/components/SettingsCard/SettingsCard';
import { SettingsLayout } from '../../../../shared/components/SettingsLayout/SettingsLayout';
import { Button } from '../../../../shared/xguard-ui/components/Button/Button';
import { EvenSplit } from '../../../../shared/xguard-ui/components/EvenSplit/EvenSplit';
import { InfoBanner } from '../../../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import { Input } from '../../../../shared/xguard-ui/components/Input/Input';
import { MarkedSection } from '../../../../shared/xguard-ui/components/MarkedSection/MarkedSection';
import { MarkedSectionHeader } from '../../../../shared/xguard-ui/components/MarkedSectionHeader/MarkedSectionHeader';
import { SectionSelect } from '../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';

export const SettingsGeneralTab = () => {
  const { data: limits } = useQuery({
    queryKey: ['device-limits'],
    queryFn: () => api.deviceLimits.getOverview().then((r) => r.data),
  });

  const [maxDevices, setMaxDevices] = useState('0');
  const [maxConnections, setMaxConnections] = useState('0');

  useEffect(() => {
    if (limits) {
      setMaxDevices(String(limits.max_devices_per_user));
      setMaxConnections(String(limits.max_connections_per_user));
    }
  }, [limits]);

  const { mutate: saveLimits, isPending } = useMutation({
    mutationFn: api.deviceLimits.updateDefaults,
    meta: { invalidate: [['device-limits'], ['activity-log']] },
    onSuccess: () => Snackbar.default(m.settings_device_limits_saved()),
    onError: () => Snackbar.error(m.settings_device_limits_save_failed()),
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const devicesVal = Number.parseInt(maxDevices, 10);
    const connsVal = Number.parseInt(maxConnections, 10);
    if (
      Number.isNaN(devicesVal) ||
      devicesVal < 0 ||
      Number.isNaN(connsVal) ||
      connsVal < 0
    ) {
      Snackbar.error(m.settings_device_limits_save_failed());
      return;
    }
    saveLimits({
      max_devices_per_user: devicesVal,
      max_connections_per_user: connsVal,
    });
  };

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
      <SizedBox height={ThemeSpacing.Xl} />
      <Link to="/settings/client-downloads">
        <SectionSelect
          image="device-clc"
          title={m.settings_client_downloads_title()}
          content={m.settings_client_downloads_subtitle()}
        />
      </Link>
      <SizedBox height={ThemeSpacing.Xl} />
      <SettingsCard>
        <MarkedSection icon="settings">
          <MarkedSectionHeader
            title={m.settings_device_limits_title()}
            description={m.settings_device_limits_description()}
          />
          <SizedBox height={ThemeSpacing.Md} />
          <InfoBanner
            variant="info"
            icon="info-outlined"
            text={m.settings_device_limits_precedence_note()}
          />
          <SizedBox height={ThemeSpacing.Lg} />
          <form onSubmit={handleSave}>
            <EvenSplit>
              <Input
                type="number"
                label={m.settings_device_limits_max_devices()}
                helper={m.settings_device_limits_helper_zero()}
                value={maxDevices}
                onChange={(val) => setMaxDevices(val == null ? '' : String(val))}
              />
              <Input
                type="number"
                label={m.settings_device_limits_max_connections()}
                helper={m.settings_device_limits_helper_zero()}
                value={maxConnections}
                onChange={(val) => setMaxConnections(val == null ? '' : String(val))}
              />
            </EvenSplit>
            <SizedBox height={ThemeSpacing.Lg} />
            <Button
              type="submit"
              text={m.controls_save_changes()}
              loading={isPending}
              data-testid="save-device-limits"
            />
          </form>
        </MarkedSection>
      </SettingsCard>
    </SettingsLayout>
  );
};
