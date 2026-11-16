import { IconButton } from '../../../xguard-ui/components/IconButton/IconButton';
import { isPresent } from '../../../xguard-ui/utils/isPresent';
import { NavLogo } from '../../Navigation/assets/NavLogo';
import './style.scss';

type Props = {
  onClick?: () => void;
};

export const WizardTop = ({ onClick }: Props) => {
  return (
    <div className={`wizard-top ${isPresent(onClick) ? 'closeable' : ''}`}>
      <div className="content-track">
        <NavLogo />
        {isPresent(onClick) && <IconButton icon="close" onClick={onClick} />}
      </div>
    </div>
  );
};
