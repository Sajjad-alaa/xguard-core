import './style.scss';
import clsx from 'clsx';
import dayjs from 'dayjs';
import { m } from '../../../../paraglide/messages';
import { AppText } from '../../../xguard-ui/components/AppText/AppText';
import { ExternalLink } from '../../../xguard-ui/components/ExternalLink/ExternalLink';
import { SizedBox } from '../../../xguard-ui/components/SizedBox/SizedBox';
import { TextStyle, ThemeSpacing, ThemeVariable } from '../../../xguard-ui/types';
import { isPresent } from '../../../xguard-ui/utils/isPresent';
import type { WizardWelcomePageConfig } from '../types';
import { WizardTop } from '../WizardTop/WizardTop';
import fileIcon from './assets/file_icon.png';
import defaultGlobe from './assets/world_map.png';

type Props = WizardWelcomePageConfig;

export const WizardWelcomePage = ({
  title,
  subtitle,
  content,
  media,
  containerProps,
  docsLink = 'https://docs.xguard.local/',
  docsText = m.initial_setup_wizard_welcome_docs_description(),
  displayDocs = true,
  onClose,
}: Props) => {
  return (
    <div
      {...containerProps}
      className={clsx('wizard-welcome-page', containerProps?.className)}
    >
      <WizardTop onClick={onClose} />
      <SizedBox height={ThemeSpacing.Xl4} />
      <div className="content">
        <div className="main-track">
          <div className="top-content">
            <h1>{title}</h1>
            <SizedBox height={ThemeSpacing.Lg} />
            <AppText font={TextStyle.TBodyPrimary400} color={ThemeVariable.FgFaded}>
              {subtitle}
            </AppText>
            <div className="left">{content}</div>
          </div>
          {displayDocs && (
            <div id="docs-card">
              <div className="image-track">
                <img src={fileIcon} alt={m.initial_setup_wizard_welcome_docs_alt()} />
              </div>

              <div className="content">
                <p>{docsText}</p>
                <div>
                  <ExternalLink href={docsLink}>
                    {m.initial_setup_wizard_welcome_docs_link()}
                  </ExternalLink>
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="media-track">
          {media}
          {!isPresent(media) && (
            <img src={defaultGlobe} alt="default globe" id="default-globe-media-image" />
          )}
        </div>
      </div>
      <div className="footer">
        <p>{m.footer_copyright({ year: dayjs().year() })}</p>
        <p>
          {m.initial_setup_wizard_footer_support_text()}{' '}
          <a href="mailto:support@xguard.local" className="mail">
            support@xguard.local
          </a>
        </p>
      </div>
    </div>
  );
};
