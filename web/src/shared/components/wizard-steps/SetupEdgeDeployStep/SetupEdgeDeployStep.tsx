import './style.scss';
import { type ReactNode, useMemo, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import { AppText } from '../../../xguard-ui/components/AppText/AppText';
import { Button } from '../../../xguard-ui/components/Button/Button';
import { Checkbox } from '../../../xguard-ui/components/Checkbox/Checkbox';
import { Icon, IconKind } from '../../../xguard-ui/components/Icon';
import { RenderMarkdown } from '../../../xguard-ui/components/RenderMarkdown/RenderMarkdown';
import { SizedBox } from '../../../xguard-ui/components/SizedBox/SizedBox';
import { Tabs } from '../../../xguard-ui/components/Tabs/Tabs';
import type { TabsItem } from '../../../xguard-ui/components/Tabs/types';
import { TooltipContent } from '../../../xguard-ui/providers/tooltip/TooltipContent';
import { TooltipProvider } from '../../../xguard-ui/providers/tooltip/TooltipContext';
import { TooltipTrigger } from '../../../xguard-ui/providers/tooltip/TooltipTrigger';
import { TextStyle, ThemeSpacing, ThemeVariable } from '../../../xguard-ui/types';
import { isPresent } from '../../../xguard-ui/utils/isPresent';
import { Card } from '../../Card/Card';
import { CodeSnippet } from '../../CodeSnippet/CodeSnippet';
import { Controls } from '../../Controls/Controls';
import { WizardCard } from '../../wizard/WizardCard/WizardCard';
import amazonImage from './assets/amazon.png';
import kubernetesImage from './assets/kub.png';
import teraImage from './assets/terra.png';

type TabItem = 'docker' | 'compose' | 'package' | 'virtualImage' | 'other';

interface SetupEdgeDeployStepProps {
  onBack?: () => void;
  onNext: () => void;
}

export const SetupEdgeDeployStep = ({ onBack, onNext }: SetupEdgeDeployStepProps) => {
  const [confirmed, setConfirmed] = useState(false);
  const [activeTab, setActiveTab] = useState<TabItem>('docker');

  const tabsConfig = useMemo(
    (): TabsItem[] => [
      {
        title: m.edge_setup_step_deploy_tabs_docker(),
        onClick: () => setActiveTab('docker'),
        active: activeTab === 'docker',
        hidden: false,
      },
      {
        title: m.edge_setup_step_deploy_tabs_compose(),
        onClick: () => setActiveTab('compose'),
        active: activeTab === 'compose',
        hidden: false,
      },
      {
        title: m.edge_setup_step_deploy_tabs_package(),
        onClick: () => setActiveTab('package'),
        active: activeTab === 'package',
        hidden: false,
      },
      {
        title: m.edge_setup_step_deploy_tabs_virtual_image(),
        onClick: () => setActiveTab('virtualImage'),
        active: activeTab === 'virtualImage',
        hidden: false,
      },
      {
        title: m.edge_setup_step_deploy_tabs_other(),
        onClick: () => setActiveTab('other'),
        active: activeTab === 'other',
        hidden: false,
      },
    ],
    [activeTab],
  );
  return (
    <WizardCard id="edge-deploy-step">
      <Tabs items={tabsConfig} disablePadding />
      <SizedBox height={ThemeSpacing.Xl2} />
      {tabsContent[activeTab]}
      <SizedBox height={ThemeSpacing.Xl2} />
      <Checkbox
        active={confirmed}
        onClick={() => {
          setConfirmed((s) => !s);
        }}
        text={m.edge_setup_step_deploy_confirm()}
        testId="edge-deploy-confirmed"
      />
      <Controls>
        {isPresent(onBack) && (
          <Button variant={'outlined'} text={m.controls_back()} onClick={onBack} />
        )}
        <div className="right">
          <TooltipProvider disabled={confirmed}>
            <TooltipTrigger>
              <div>
                <Button
                  text={m.controls_continue()}
                  disabled={!confirmed}
                  onClick={onNext}
                />
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p>{m.edge_setup_step_deploy_confirm_tooltip()}</p>
            </TooltipContent>
          </TooltipProvider>
        </div>
      </Controls>
    </WizardCard>
  );
};

const TabContentHeader = ({ subtitle, title }: { title: string; subtitle: string }) => {
  return (
    <div className="tab-content-header">
      <AppText font={TextStyle.TBodyPrimary500}>{title}</AppText>
      <SizedBox height={ThemeSpacing.Sm} />
      <RenderMarkdown content={subtitle} />
      <SizedBox height={ThemeSpacing.Md} />
    </div>
  );
};

const DockerComposeTab = () => {
  return (
    <>
      <TabContentHeader
        title={m.edge_setup_step_deploy_tabs_compose_title()}
        subtitle={m.edge_setup_step_deploy_tabs_compose_subtitle({
          filename: `docker-compose.yaml`,
        })}
      />
      <CodeSnippet
        value={`services:
  edge:
    image: ghcr.io/sajjad-alaa/xguard-proxy:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "50051:50051"
      - "443:443"
    # Uncomment if you'd like XGuard to provision a certificate using Let's Encrypt.
    #  - "80:80"
    # Uncomment the following if you are running on Debian 13 or later or have apparmor or SELinux setup
    #security_opt:
    #  - apparmor:unconfined
    volumes:
      - ./.volumes/certs/edge:/etc/xguard/certs`}
      />
      <SizedBox height={ThemeSpacing.Xl2} />
      <AppText font={TextStyle.TBodySm400}>
        {m.edge_setup_step_deploy_tabs_compose_then()}
      </AppText>
      <SizedBox height={ThemeSpacing.Md} />
      <CodeSnippet value={`docker compose up -d`} />
    </>
  );
};

const DockerTab = () => {
  return (
    <>
      <TabContentHeader
        title={m.edge_setup_step_deploy_tabs_docker_title()}
        subtitle={m.edge_setup_step_deploy_tabs_docker_subtitle()}
      />
      <CodeSnippet
        value={`docker run --restart unless-stopped --security-opt apparmor:unconfined -p 8080:8080 -p 50051:50051 -p 443:443 -p 80:80 -v ./.volumes/certs/edge:/etc/xguard/certs ghcr.io/sajjad-alaa/xguard-proxy:latest`}
      />
    </>
  );
};

const PackageTab = () => {
  return (
    <>
      <TabContentHeader
        title={m.edge_setup_step_deploy_tabs_package_title()}
        subtitle={m.edge_setup_step_deploy_tabs_package_subtitle()}
      />
      <CodeSnippet
        value={`sudo apt update
sudo apt install -y ca-certificates curl
#Add official XGuard public GPG key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://apt.xguard.local/xguard.asc -o /etc/apt/keyrings/xguard.asc
sudo chmod a+r /etc/apt/keyrings/xguard.asc

#Add APT repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/xguard.asc] https://apt.xguard.local/ trixie release-2.0 " | \
   sudo tee /etc/apt/sources.list.d/xguard.list > /dev/null

sudo apt update
sudo apt install xguard-proxy`}
      />
    </>
  );
};

const VirtualImageTab = () => {
  return (
    <>
      <TabContentHeader
        title={m.edge_setup_step_deploy_tabs_virtual_title()}
        subtitle={m.edge_setup_step_deploy_tabs_virtual_subtitle({
          url: `https://xguard-downloads.s3.eu-central-1.amazonaws.com/ova/xguard-latest.ova`,
          filename: `xguard-data.yaml`,
        })}
      />
      <CodeSnippet
        value={`#cloud-config
write_files:
  - path: /opt/stacks/xguard/active-profiles
    permissions: '0644'
    content: |
      edge
`}
      />
    </>
  );
};

const OtherDeploymentMethod = ({
  image,
  link,
  name,
}: {
  image: string;
  name: string;
  link: string;
}) => {
  return (
    <Card>
      <div className="inner-track">
        <div className="image-tack">
          <img src={image} width={44} height={44} />
        </div>
        <div className="content">
          <p className="title">{name}</p>
          <a target="_blank" rel="noopener noreferrer" href={link}>
            <span>{link}</span>
            <Icon icon={IconKind.OpenInNewWindow} size={16} />
          </a>
        </div>
      </div>
    </Card>
  );
};

const OthersTab = () => {
  return (
    <>
      <TabContentHeader
        title={m.edge_setup_step_deploy_tabs_other_title()}
        subtitle={m.edge_setup_step_deploy_tabs_other_subtitle()}
      />
      <div id="other-deployment-methods">
        <OtherDeploymentMethod
          name={`Kubernetes`}
          link={`https://docs.xguard.local/deployment-strategies/kubernetes#deployment`}
          image={kubernetesImage}
        />
        <OtherDeploymentMethod
          name={`Amazon Machine Image`}
          link={`https://docs.xguard.local/deployment-strategies/amis-and-aws-cloudformation`}
          image={amazonImage}
        />
        <OtherDeploymentMethod
          name={`Terraform`}
          link={`https://docs.xguard.local/deployment-strategies/terraform`}
          image={teraImage}
        />
      </div>
      <SizedBox height={ThemeSpacing.Lg} />
      <AppText font={TextStyle.TBodySm400} color={ThemeVariable.FgFaded}>
        {m.edge_setup_step_deploy_tabs_other_launch()}
      </AppText>
    </>
  );
};

const tabsContent: Record<TabItem, ReactNode> = {
  docker: <DockerTab />,
  compose: <DockerComposeTab />,
  package: <PackageTab />,
  virtualImage: <VirtualImageTab />,
  other: <OthersTab />,
};
