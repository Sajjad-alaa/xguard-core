import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { m } from '../../../../../paraglide/messages';
import api from '../../../../../shared/api/api';
import { LayoutGrid } from '../../../../../shared/components/LayoutGrid/LayoutGrid';
import './style.scss';
import { AddUserDeviceModal } from '../../../../../shared/components/modals/AddUserDeviceModal/AddUserDeviceModal';
import { AssignUserDeviceIPModal } from '../../../../../shared/components/modals/AssignUserDeviceIPModal/AssignUserDeviceIPModal';
import { DevicePostureModal } from '../../../../../shared/components/modals/DevicePostureModal/DevicePostureModal';
import { EditUserDeviceModal } from '../../../../../shared/components/modals/EditUserDeviceModal/EditUserDeviceModal';
import { UserDeviceConfigModal } from '../../../../../shared/components/modals/UserDeviceConfigModal/UserDeviceConfigModal';
import { useAuth } from '../../../../../shared/hooks/useAuth';
import { Badge } from '../../../../../shared/xguard-ui/components/Badge/Badge';
import { BadgeVariant } from '../../../../../shared/xguard-ui/components/Badge/types';
import { Button } from '../../../../../shared/xguard-ui/components/Button/Button';
import { Divider } from '../../../../../shared/xguard-ui/components/Divider/Divider';
import { EvenSplit } from '../../../../../shared/xguard-ui/components/EvenSplit/EvenSplit';
import { Input } from '../../../../../shared/xguard-ui/components/Input/Input';
import { MarkedSection } from '../../../../../shared/xguard-ui/components/MarkedSection/MarkedSection';
import { MarkedSectionHeader } from '../../../../../shared/xguard-ui/components/MarkedSectionHeader/MarkedSectionHeader';
import { SizedBox } from '../../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../../shared/xguard-ui/types';
import { useUserProfile } from '../../hooks/useUserProfilePage';
import { ProfileDevicesTable } from './components/ProfileDevicesTable/ProfileDevicesTable';

export const ProfileDevicesTab = () => {
  const user = useUserProfile((s) => s.user);
  const { isAdmin } = useAuth();

  const { data: limitInfo } = useQuery({
    queryKey: ['device-limits', 'user', user.id],
    queryFn: () => api.deviceLimits.getUserLimit(user.id).then((r) => r.data),
  });

  const [maxDevices, setMaxDevices] = useState('');
  const [maxConnections, setMaxConnections] = useState('');

  useEffect(() => {
    if (limitInfo) {
      setMaxDevices(
        limitInfo.override_max_devices != null
          ? String(limitInfo.override_max_devices)
          : '',
      );
      setMaxConnections(
        limitInfo.override_max_connections != null
          ? String(limitInfo.override_max_connections)
          : '',
      );
    }
  }, [limitInfo]);

  const { mutate: saveOverride, isPending } = useMutation({
    mutationFn: (data: { max_devices: number | null; max_connections: number | null }) =>
      api.deviceLimits.setUserLimit(user.id, data),
    meta: { invalidate: [['device-limits', 'user', user.id], ['activity-log']] },
    onSuccess: () => Snackbar.default(m.settings_device_limits_saved()),
    onError: () => Snackbar.error(m.settings_device_limits_save_failed()),
  });

  const parseOptional = (raw: string): number | null => {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const parsed = Number.parseInt(trimmed, 10);
    return Number.isNaN(parsed) || parsed < 0 ? null : parsed;
  };

  const quotaPct =
    limitInfo && limitInfo.effective_max_devices > 0
      ? Math.min(
          100,
          Math.round((limitInfo.device_count / limitInfo.effective_max_devices) * 100),
        )
      : null;

  const quotaStatus =
    quotaPct == null
      ? null
      : quotaPct >= 100
        ? 'exceeded'
        : quotaPct >= 80
          ? 'warning'
          : 'healthy';

  return (
    <>
      <LayoutGrid id="profile-devices-tab">
        {limitInfo && (
          <div className="device-limits-card">
            <MarkedSection icon="settings">
              <div className="quota-header-row">
                <MarkedSectionHeader
                  title={m.settings_device_limits_title()}
                  description={
                    limitInfo.effective_max_devices > 0
                      ? m.settings_device_limits_usage_limited({
                          count: limitInfo.device_count,
                          limit: limitInfo.effective_max_devices,
                        })
                      : m.settings_device_limits_usage_unlimited({
                          count: limitInfo.device_count,
                        })
                  }
                />
                <div className="quota-badges">
                  {quotaStatus && (
                    <Badge
                      variant={
                        quotaStatus === 'exceeded'
                          ? BadgeVariant.Critical
                          : quotaStatus === 'warning'
                            ? BadgeVariant.Warning
                            : BadgeVariant.Success
                      }
                      text={
                        quotaStatus === 'exceeded'
                          ? m.settings_device_limits_quota_exceeded()
                          : quotaStatus === 'warning'
                            ? m.settings_device_limits_quota_warning()
                            : m.settings_device_limits_quota_healthy()
                      }
                      showIcon
                    />
                  )}
                  <Badge
                    variant={BadgeVariant.Default}
                    text={m.settings_device_limits_effective_connections({
                      limit:
                        limitInfo.effective_max_connections > 0
                          ? String(limitInfo.effective_max_connections)
                          : m.settings_device_limits_unlimited_label(),
                    })}
                  />
                </div>
              </div>
              {quotaPct != null && quotaStatus && (
                <div
                  className="quota-bar-track"
                  role="progressbar"
                  aria-valuenow={limitInfo.device_count}
                  aria-valuemin={0}
                  aria-valuemax={limitInfo.effective_max_devices}
                >
                  <div
                    className={`quota-bar-fill status-${quotaStatus}`}
                    style={{ width: `${quotaPct}%` }}
                  />
                </div>
              )}
              {isAdmin && (
                <>
                  <Divider spacing={ThemeSpacing.Lg} />
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      saveOverride({
                        max_devices: parseOptional(maxDevices),
                        max_connections: parseOptional(maxConnections),
                      });
                    }}
                  >
                    <EvenSplit>
                      <Input
                        type="number"
                        label={m.settings_device_limits_max_devices()}
                        helper={m.settings_device_limits_helper_override()}
                        value={maxDevices}
                        onChange={(val) => setMaxDevices(val == null ? '' : String(val))}
                      />
                      <Input
                        type="number"
                        label={m.settings_device_limits_max_connections()}
                        helper={m.settings_device_limits_helper_override()}
                        value={maxConnections}
                        onChange={(val) =>
                          setMaxConnections(val == null ? '' : String(val))
                        }
                      />
                    </EvenSplit>
                    <SizedBox height={ThemeSpacing.Md} />
                    <Button
                      type="submit"
                      text={m.controls_save_changes()}
                      loading={isPending}
                      data-testid="save-user-device-limits"
                    />
                  </form>
                </>
              )}
            </MarkedSection>
          </div>
        )}
        <ProfileDevicesTable />
      </LayoutGrid>
      <AddUserDeviceModal />
      <EditUserDeviceModal />
      <UserDeviceConfigModal />
      <AssignUserDeviceIPModal />
      <DevicePostureModal />
    </>
  );
};
