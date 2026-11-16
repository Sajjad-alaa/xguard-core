import { useMutation } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { cloneDeep, omit } from 'lodash-es';
import { useCallback, useState } from 'react';
import { m } from '../../../paraglide/messages';
import api from '../../../shared/api/api';
import { ActionCard } from '../../../shared/components/ActionCard/ActionCard';
import { Controls } from '../../../shared/components/Controls/Controls';
import { WizardCard } from '../../../shared/components/wizard/WizardCard/WizardCard';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { Checkbox } from '../../../shared/xguard-ui/components/Checkbox/Checkbox';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { Radio } from '../../../shared/xguard-ui/components/Radio/Radio';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { useGatewayWizardStore } from '../../GatewaySetupPage/useGatewayWizardStore';
import actionCardImage from '../assets/gateway-setup-action-card.png';
import { AddLocationPageStep } from '../types';
import { useAddLocationStore } from '../useAddLocationStore';

type Choice = 'disable' | 'enabled-allowed' | 'enabled-denied';

export const AddLocationFirewallStep = () => {
  const [state, setState] = useState<Choice>(() => {
    const { acl_enabled, acl_default_allow } = useAddLocationStore.getState();
    if (!acl_enabled) return 'disable';
    return acl_default_allow ? 'enabled-allowed' : 'enabled-denied';
  });
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

  const saveChanges = useCallback((value: Choice) => {
    useAddLocationStore.setState({
      acl_enabled: value !== 'disable',
      acl_default_allow: value === 'enabled-allowed',
    });
  }, []);

  const handleSubmit = () => {
    saveChanges(state);
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
      <Radio
        active={state === 'disable'}
        onClick={() => setState('disable')}
        text={m.location_firewall_option_disabled()}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <Radio
        active={state === 'enabled-allowed'}
        onClick={() => setState('enabled-allowed')}
        text={m.location_firewall_option_default_allow()}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <Radio
        active={state === 'enabled-denied'}
        onClick={() => setState('enabled-denied')}
        text={m.location_firewall_option_default_deny()}
      />
      <Divider spacing={ThemeSpacing.Xl2} />
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
            saveChanges(state);
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
