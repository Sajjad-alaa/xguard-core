import './style.scss';
import { useQuery } from '@tanstack/react-query';
import { Reorder } from 'motion/react';
import { useCallback, useRef, useState } from 'react';
import { m } from '../../../paraglide/messages';
import {
  type MfaFlowMethodValue,
  MfaMethodAvailabilityReason,
  type MfaMethodAvailabilityReasonValue,
} from '../../api/types';
import { getMfaMethodAvailabilityQueryOptions } from '../../query';
import { mfaFlowMethodHints, mfaFlowMethodLabels } from '../../utils/mfaFlowSteps';
import type { ButtonProps } from '../../xguard-ui/components/Button/types';
import { FieldError } from '../../xguard-ui/components/FieldError/FieldError';
import { MfaConfigurationStep } from './components/MfaConfigurationStep';
import { MfaMethodsMenu } from './components/MfaMethodsMenu';
import type {
  MfaConfigurationMethodGroup,
  MfaConfigurationProps,
  MfaConfigurationStepData,
} from './types';

const getDisabledHelper = (reason: MfaMethodAvailabilityReasonValue) => {
  switch (reason) {
    case MfaMethodAvailabilityReason.NotSupported:
      return m.mfa_flow_method_not_supported();
    case MfaMethodAvailabilityReason.SmtpNotConfigured:
      return m.mfa_flow_method_smtp_required();
    case MfaMethodAvailabilityReason.OidcProviderMissing:
      return m.mfa_flow_error_oidc_provider_missing();
    case MfaMethodAvailabilityReason.RadiusNotConfigured:
      return m.mfa_flow_error_radius_not_configured();
    case MfaMethodAvailabilityReason.Available:
      return undefined;
  }
};

export const MfaConfiguration = ({ onChange, steps, error }: MfaConfigurationProps) => {
  const stepsTrackRef = useRef<HTMLUListElement>(null);
  const [isReordering, setReordering] = useState(false);
  const { data: methodData } = useQuery(getMfaMethodAvailabilityQueryOptions);
  const methodAvailability = methodData?.methodAvailability;
  const methods = methodData?.methods ?? [];

  const buildOption = useCallback(
    (method: MfaFlowMethodValue, onClick: () => void) => {
      const availability = methodAvailability?.find((item) => item.method === method);
      const unavailableText = availability
        ? getDisabledHelper(availability.reason)
        : undefined;
      const hint = mfaFlowMethodHints[method];
      return {
        text: mfaFlowMethodLabels[method],
        onClick,
        disabled: availability?.available !== true,
        helper: unavailableText
          ? { text: unavailableText, icon: 'lock-closed' as const }
          : hint
            ? { text: hint.description, icon: hint.icon }
            : undefined,
      };
    },
    [methodAvailability],
  );
  // Every method is offered; unavailable ones are disabled with the reason as their helper.
  const buildMethodGroups = (
    methods: MfaFlowMethodValue[],
  ): MfaConfigurationMethodGroup[] => [{ items: methods }];

  const addStepMenuOptions = buildMethodGroups(methods).map((group) => ({
    ...group,
    items: group.items.map((method) => ({
      ...buildOption(method, () => {
        onChange([...steps, { id: crypto.randomUUID(), methods: [method] }]);
      }),
      testId: `add-mfa-step-method-${method}`,
    })),
  }));
  const addStepButtonProps: Omit<ButtonProps, 'ref'> = {
    type: 'button',
    testId: 'add-mfa-step',
    variant: 'outlined',
    iconRight: 'arrow-small',
    iconRightRotation: 'down',
    text: m.mfa_flow_step_add(),
    disabled: methodAvailability === undefined,
  };

  const deleteStep = useCallback(
    (id: MfaConfigurationStepData['id']) => {
      onChange(steps.filter((step) => step.id !== id));
    },
    [onChange, steps],
  );

  const addMethod = useCallback(
    (stepId: MfaConfigurationStepData['id'], method: MfaFlowMethodValue) => {
      onChange(
        steps.map((step) =>
          step.id === stepId ? { ...step, methods: [...step.methods, method] } : step,
        ),
      );
    },
    [onChange, steps],
  );

  const deleteMethod = useCallback(
    (stepId: MfaConfigurationStepData['id'], method: MfaFlowMethodValue) => {
      onChange(
        steps.map((item) =>
          item.id === stepId
            ? {
                ...item,
                methods: item.methods.filter((itemMethod) => itemMethod !== method),
              }
            : item,
        ),
      );
    },
    [onChange, steps],
  );

  return (
    <div className="mfa-configuration">
      <Reorder.Group
        ref={stepsTrackRef}
        axis="y"
        values={steps}
        onReorder={onChange}
        className="steps-track"
      >
        {steps.map((step, index) => (
          <MfaConfigurationStep
            key={step.id}
            step={step}
            stepNumber={index + 1}
            dragConstraints={stepsTrackRef}
            isReordering={isReordering}
            onReorderingChange={setReordering}
            methodGroups={buildMethodGroups(
              methods.filter((method) => !step.methods.includes(method)),
            )}
            methodLabels={mfaFlowMethodLabels}
            onDeleteStep={deleteStep}
            onAddMethod={addMethod}
            onDeleteMethod={deleteMethod}
            buildOption={buildOption}
          />
        ))}
      </Reorder.Group>
      <div className="actions">
        <MfaMethodsMenu
          {...addStepButtonProps}
          kind="button"
          options={addStepMenuOptions}
        />
      </div>
      <FieldError error={steps.length === 0 ? error : undefined} />
    </div>
  );
};
