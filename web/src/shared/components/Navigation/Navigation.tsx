import { useState } from 'react';
import { m } from '../../../paraglide/messages';
import { useApp } from '../../hooks/useApp';
import { useAuth } from '../../hooks/useAuth';
import { CounterLabel } from '../../xguard-ui/components/CounterLabel/CounterLabel';
import { Icon } from '../../xguard-ui/components/Icon';
import type { IconKindValue } from '../../xguard-ui/components/Icon/icon-types';
import { IconButton } from '../../xguard-ui/components/IconButton/IconButton';
import { NavLogo } from './assets/NavLogo';
import './style.scss';
import { Link, type LinkProps } from '@tanstack/react-router';
import { NavTutorialsButton } from '../../video-tutorials/components/widget/NavTutorialsButton/NavTutorialsButton';
import { useVideoTutorialsSections } from '../../video-tutorials/resolved';
import { Fold } from '../../xguard-ui/components/Fold/Fold';
import { isPresent } from '../../xguard-ui/utils/isPresent';

interface NavGroupProps {
  id: string;
  label: string;
  items: NavItemProps[];
}

interface NavItemProps {
  id: string;
  label: string;
  icon: IconKindValue;
  link: LinkProps['to'];
  testId?: string;
  pendingCount?: number;
}

const navigationConfig: NavGroupProps[] = [
  {
    id: 'vpn',
    label: m.cmp_nav_group_vpn(),
    items: [
      {
        id: 'overview',
        icon: 'pie-chart',
        label: m.cmp_nav_item_overview(),
        link: '/vpn-overview',
      },
      {
        id: 'locations',
        icon: 'location-tracking',
        label: m.cmp_nav_item_locations(),
        link: '/locations',
      },
      {
        id: 'firewall',
        icon: 'protection',
        label: m.firewall_nav(),
        link: '/firewall',
      },
      {
        id: 'posture_checks',
        icon: 'connected-devices',
        label: m.cmp_nav_item_posture_checks(),
        link: '/posture-checks',
      },
    ],
  },
  {
    id: 'identity',
    label: m.cmp_nav_group_identity(),
    items: [
      {
        id: 'users',
        icon: 'users',
        label: m.cmp_nav_item_users(),
        link: '/users',
      },
      {
        id: 'groups',
        icon: 'groups',
        label: m.cmp_nav_item_groups(),
        link: '/groups',
        testId: 'groups',
      },
      {
        id: 'enrollment',
        icon: 'key',
        label: m.cmp_nav_item_enrollment(),
        link: '/enrollment',
      },
      {
        id: 'mfa',
        icon: 'mobile-lock',
        label: m.cmp_nav_item_mfa(),
        link: '/mfa',
      },
    ],
  },
  {
    id: 'integrations',
    label: m.cmp_nav_group_integrations(),
    items: [
      {
        id: 'activity_log',
        icon: 'activity',
        label: m.cmp_nav_item_activity_log(),
        link: '/activity',
      },
      {
        id: 'network_devices',
        icon: 'devices',
        label: m.cmp_nav_item_network_devices(),
        link: '/network-devices',
      },
      {
        id: 'openid',
        icon: 'openid',
        label: m.cmp_nav_item_openid(),
        link: '/openid',
      },
      {
        id: 'webhooks',
        icon: 'webhooks',
        label: m.cmp_nav_item_webhooks(),
        link: '/webhooks',
      },
    ],
  },
  {
    id: 'admin',
    label: m.cmp_nav_group_admin(),
    items: [
      {
        id: 'settings',
        icon: 'settings',
        label: m.cmp_nav_item_settings(),
        link: '/settings',
      },
      {
        id: 'support',
        icon: 'support',
        label: m.cmp_nav_item_support(),
        link: '/support',
      },
      {
        id: 'edges',
        icon: 'globe',
        label: m.cmp_nav_item_edges(),
        link: '/edges',
      },
    ],
  },
];

export const Navigation = () => {
  const isAdmin = useAuth((s) => s.isAdmin);
  const isOpen = useApp((s) => s.navigationOpen);

  const videoTutorialSections = useVideoTutorialsSections();
  const hasTutorialSections = videoTutorialSections.some(
    (section) => section.videos.length > 0,
  );

  const navigationGroups = navigationConfig;

  const rawVersion = useApp((s) => s.appInfo.version);
  const semverVersion = rawVersion ? rawVersion.split('+')[0] : null;

  if (!isAdmin || !isOpen) return null;
  return (
    <div className="navigation">
      <div className="top">
        <NavLogo />
        {semverVersion && <span className="version-badge">{semverVersion}</span>}
        <div className="control">
          <IconButton
            icon="hamburger"
            onClick={() => {
              useApp.setState({
                navigationOpen: false,
              });
            }}
          />
        </div>
      </div>
      <div className="groups">
        {navigationGroups.map((group) => (
          <NavGroup key={group.id} {...group} />
        ))}
      </div>
      <div className="bottom">
        {hasTutorialSections && (
          <div className="nav-group">
            <NavTutorialsButton />
          </div>
        )}
      </div>
    </div>
  );
};

const NavGroup = ({ items, label }: NavGroupProps) => {
  const [isOpen, setIsOpen] = useState(true);
  return (
    <div className="nav-group">
      <div
        className="track"
        onClick={() => {
          setIsOpen((s) => !s);
        }}
      >
        <Icon icon="arrow-small" rotationDirection={isOpen ? 'down' : 'right'} />
        <p>{label}</p>
      </div>
      <Fold open={isOpen}>
        <div className="items">
          {items.map((item) => (
            <NavItem key={item.id} {...item} />
          ))}
        </div>
      </Fold>
    </div>
  );
};

const NavItem = ({ icon, link, label, testId, pendingCount }: NavItemProps) => {
  const showPending = isPresent(pendingCount) && pendingCount > 0;

  return (
    <Link to={link} className="nav-item" data-testid={testId}>
      <Icon icon={icon} />
      <span>{label}</span>
      {showPending && (
        <div className="right">
          <CounterLabel value={pendingCount} variant="warning" />
        </div>
      )}
    </Link>
  );
};
