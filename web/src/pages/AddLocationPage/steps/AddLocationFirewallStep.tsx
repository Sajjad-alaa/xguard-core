import { useMutation } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { cloneDeep, omit } from 'lodash-es';
import { useState } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { ActionCard } from '../../../shared/components/ActionCard/ActionCard';
import { Controls } from '../../../shared/components/Controls/Controls';
import { WizardCard } from '../../../shared/components/wizard/WizardCard/WizardCard';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { Checkbox } from '../../../shared/xguard-ui/components/Checkbox/Checkbox';
import { useGatewayWizardStore } from '../../GatewaySetupPage/useGatewayWizardStore';
import actionCardImage from '../assets/gateway-setup-action-card.png';
import { AddLocationPageStep } from '../types';
import { useAddLocationStore } from '../useAddLocationStore';

export const AddLocationFirewallStep = () => {
  const [showGateway, setShowGateway] = useState(true);
  const navigate = useNavigate();

  const { mutate, isPending } = useMutation({
    mutationFn: api.location.addLocation,
    meta: {
      invalidate: [['network'], ['mfa-flow']],
    },
    onSuccess: ({ data }) => {
      if (showGateway) {
        useGatewayWizardStore.getState().start({ network_id: data.id });
        navigate({ to: '/setup-gateway', replace: true }).then(() => {
          setTimeout(() => {
            useAddLocationStore.getState().reset();
          }, 100);
        });
      } else {
        navigate({ to: '/locations', replace: true }).then(() => {
          setTimeout(() => {
            useAddLocationStore.getState().reset();
          }, 100);
        });
      }
    },
  });

  const handleSubmit = () => {
    // XGuard has no firewall (ACL) support: locations are created with it disabled.
    useAddLocationStore.setState({ acl_enabled: false, acl_default_allow: false });
    const storageState = cloneDeep(
      omit(useAddLocationStore.getState(), [
        'start',
        'reset',
        'activeStep',
        'locationType',
      ]),
    );
    mutate(storageState);
  };

  return (
    <WizardCard>
      <ActionCard
        imageSrc={actionCardImage}
        title={m.add_location_firewall_gateway_activation_title()}
        subtitle={m.add_location_firewall_gateway_activation_subtitle()}
      >
        <Checkbox
          text={m.add_location_firewall_gateway_activation_checkbox()}
          active={showGateway}
          onClick={() => {
            setShowGateway((s) => !s);
          }}
        />
      </ActionCard>
      <Controls>
        <Button
          variant="outlined"
          text={m.controls_back()}
          onClick={() => {
            useAddLocationStore.setState({
              activeStep: AddLocationPageStep.AccessControl,
            });
          }}
        />
        <div className="right">
          <Button
            testId="create-location"
            text={m.add_location_create_location()}
            loading={isPending}
            onClick={() => {
              handleSubmit();
            }}
          />
        </div>
      </Controls>
    </WizardCard>
  );
};
