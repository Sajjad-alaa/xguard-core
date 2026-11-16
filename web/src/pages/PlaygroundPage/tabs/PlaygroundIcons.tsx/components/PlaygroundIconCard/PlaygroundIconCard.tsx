import { titleCase } from 'text-case';
import {
  Icon,
  type IconKindValue,
} from '../../../../../../shared/xguard-ui/components/Icon';
import { useClipboard } from '../../../../../../shared/xguard-ui/hooks/useClipboard';
import './style.scss';
import { Snackbar } from '../../../../../../shared/xguard-ui/providers/snackbar/snackbar';
import { TooltipContent } from '../../../../../../shared/xguard-ui/providers/tooltip/TooltipContent';
import { TooltipProvider } from '../../../../../../shared/xguard-ui/providers/tooltip/TooltipContext';
import { TooltipTrigger } from '../../../../../../shared/xguard-ui/providers/tooltip/TooltipTrigger';

interface Props {
  icon: IconKindValue;
}

export const PlaygroundIconCard = ({ icon }: Props) => {
  const { writeToClipboard } = useClipboard();
  return (
    <TooltipProvider>
      <TooltipTrigger>
        <div
          className="playground-icon-card"
          onClick={() => {
            writeToClipboard(icon).then(() => {
              Snackbar.default(`Copied ${icon}`);
            });
          }}
        >
          <div className="top">
            <Icon icon={icon} />
          </div>
          <div className="bottom">
            <p>{titleCase(icon.replaceAll('-', ' '))}</p>
          </div>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <p>{icon}</p>
      </TooltipContent>
    </TooltipProvider>
  );
};
