import { Fragment } from 'react/jsx-runtime';
import { m } from '../../../../paraglide/messages';
import { externalLink } from '../../../constants';
import { Button } from '../../../xguard-ui/components/Button/Button';
import { IconKind } from '../../../xguard-ui/components/Icon';
import { SizedBox } from '../../../xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../xguard-ui/types';
import { closeModal } from '../../../hooks/modalControls/modalsSubjects';
import type { ModalNameValue } from '../../../hooks/modalControls/modalTypes';
import { Controls } from '../../Controls/Controls';

type Props = {
  modalName: ModalNameValue;
  linkText?: string;
};

export const LicenseModalControls = ({ modalName, linkText }: Props) => {
  return (
    <Fragment>
      <SizedBox height={ThemeSpacing.Xl2} />
      <Controls>
        <div className="right">
          <Button
            variant="secondary"
            text={m.controls_cancel()}
            onClick={() => {
              closeModal(modalName);
            }}
          />
          <a
            target="_blank"
            rel="noopener noreferrer"
            href={externalLink.xguard.pricing}
          >
            <Button
              text={linkText ?? m.license_see_other_plans()}
              iconRight={IconKind.OpenInNewWindow}
            />
          </a>
        </div>
      </Controls>
    </Fragment>
  );
};
