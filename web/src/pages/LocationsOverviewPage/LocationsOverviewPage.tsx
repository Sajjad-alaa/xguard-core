import './style.scss';
import { useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { useMemo } from 'react';
import { m } from '../../paraglide/messages';
import api from '../../shared/api/api';
import { OverviewPeriodSelect } from '../../shared/components/OverviewPeriodSelect/OverviewPeriodSelect';
import { Page } from '../../shared/components/Page/Page';
import { getLocationsQueryOptions } from '../../shared/query';
import { Badge } from '../../shared/xguard-ui/components/Badge/Badge';
import { BadgeSize, BadgeVariant } from '../../shared/xguard-ui/components/Badge/types';
import { Icon } from '../../shared/xguard-ui/components/Icon';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { isPresent } from '../../shared/xguard-ui/utils/isPresent';
import {
  LocationOverviewCard,
  OverviewCard,
} from './components/LocationOverviewCard/LocationOverviewCard';

export const LocationsOverviewPage = () => {
  const navigate = useNavigate();
  const { data: locations } = useSuspenseQuery(getLocationsQueryOptions);
  const { period } = useSearch({ from: '/_authorized/_default/vpn-overview/' });

  const { data: allStats } = useQuery({
    queryFn: () => api.location.getLocationsSummary(period),
    queryKey: [
      'network',
      'stats',
      'all',
      {
        from: period,
      },
    ],
    select: (resp) => resp.data,
    refetchInterval: 30_000,
  });

  const fleet = useMemo(() => {
    let totalGateways = 0;
    let onlineGateways = 0;
    let mfaCount = 0;
    let aclCount = 0;
    let postureCount = 0;

    for (const loc of locations) {
      const gws = loc.gateways ?? [];
      totalGateways += gws.length;
      onlineGateways += gws.filter((g) => g.connected).length;
      if (loc.mfa_enabled) mfaCount += 1;
      if (loc.acl_enabled) aclCount += 1;
      if ((loc.posture_checks?.length ?? 0) > 0) postureCount += 1;
    }

    return {
      totalLocations: locations.length,
      totalGateways,
      onlineGateways,
      mfaCount,
      aclCount,
      postureCount,
    };
  }, [locations]);

  const activeUsers = allStats?.current_active_users ?? 0;
  const activeDevices =
    (allStats?.current_active_user_devices ?? 0) +
    (allStats?.current_active_network_devices ?? 0);

  const gatewayBadgeVariant =
    fleet.totalGateways === 0
      ? BadgeVariant.Neutral
      : fleet.onlineGateways === fleet.totalGateways
        ? BadgeVariant.Success
        : fleet.onlineGateways > 0
          ? BadgeVariant.Warning
          : BadgeVariant.Critical;

  return (
    <Page title={m.cmp_nav_item_overview()} id="locations-overview-page">
      <SizedBox height={ThemeSpacing.Xl3} />
      <div className="top">
        <p>{m.locations_overview_dashboard()}</p>
        <div className="right">
          <OverviewPeriodSelect
            onChange={(value) => {
              navigate({
                from: '/vpn-overview/',
                search: {
                  period: value,
                },
              });
            }}
            period={period}
          />
        </div>
      </div>
      <SizedBox height={ThemeSpacing.Xl} />
      <div className="fleet-kpi-strip" data-testid="fleet-kpi-strip">
        <div className="kpi-card">
          <div className="kpi-label-row">
            <span className="kpi-label">{m.locations_overview_kpi_locations()}</span>
            <Icon icon="location" size={16} />
          </div>
          <div className="kpi-value">{fleet.totalLocations}</div>
          <div className="kpi-meta">
            <Badge
              size={BadgeSize.Compact}
              variant={fleet.mfaCount > 0 ? BadgeVariant.Success : BadgeVariant.Neutral}
              text={m.locations_overview_kpi_mfa_protected({ count: fleet.mfaCount })}
            />
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label-row">
            <span className="kpi-label">{m.locations_overview_kpi_gateways()}</span>
            <Icon icon="servers" size={16} />
          </div>
          <div className="kpi-value">
            {fleet.onlineGateways}
            <span className="kpi-denom">/ {fleet.totalGateways}</span>
          </div>
          <div className="kpi-meta">
            <Badge
              size={BadgeSize.Compact}
              variant={gatewayBadgeVariant}
              text={
                fleet.totalGateways > 0
                  ? `${Math.round((fleet.onlineGateways / fleet.totalGateways) * 100)}%`
                  : '0%'
              }
              showIcon
            />
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label-row">
            <span className="kpi-label">
              {m.locations_overview_kpi_active_sessions()}
            </span>
            <Icon icon="connected-devices" size={16} />
          </div>
          <div className="kpi-value">{activeDevices}</div>
          <div className="kpi-meta">
            <span>
              {m.locations_overview_kpi_users_devices({
                users: activeUsers,
                devices: activeDevices,
              })}
            </span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label-row">
            <span className="kpi-label">{m.locations_overview_kpi_zero_trust()}</span>
            <Icon icon="activity" size={16} />
          </div>
          <div className="kpi-value">{fleet.aclCount + fleet.postureCount}</div>
          <div className="kpi-meta">
            <Badge
              size={BadgeSize.Compact}
              variant={fleet.aclCount > 0 ? BadgeVariant.Default : BadgeVariant.Neutral}
              text={m.locations_overview_kpi_acl_enforced({ count: fleet.aclCount })}
            />
            <Badge
              size={BadgeSize.Compact}
              variant={
                fleet.postureCount > 0 ? BadgeVariant.Default : BadgeVariant.Neutral
              }
              text={m.locations_overview_kpi_posture_checked({
                count: fleet.postureCount,
              })}
            />
          </div>
        </div>
      </div>
      <SizedBox height={ThemeSpacing.Xl2} />
      <ul>
        {isPresent(allStats) && (
          <li>
            <OverviewCard
              statsPeriod={period}
              data={allStats}
              expanded={true}
              emptyStateTitle={m.locations_overview_empty_title()}
              emptyStateSubtitle={m.locations_overview_empty_subtitle()}
            >
              <div className="summary-top">
                <p>{m.locations_overview_summary_title()}</p>
              </div>
            </OverviewCard>
          </li>
        )}
        {locations.map((location) => (
          <li key={location.id}>
            <LocationOverviewCard
              location={location}
              statsPeriod={period}
              expanded={true}
              showTop
            />
          </li>
        ))}
      </ul>
    </Page>
  );
};
