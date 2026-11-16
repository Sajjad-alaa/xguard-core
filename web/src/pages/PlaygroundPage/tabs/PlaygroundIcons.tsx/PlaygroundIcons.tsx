import './style.scss';
import { IconKind } from '../../../../shared/xguard-ui/components/Icon';
import { PlaygroundIconCard } from './components/PlaygroundIconCard/PlaygroundIconCard';

const data = Object.values(IconKind);

export const PlaygroundIcons = () => {
  return (
    <div id="playground-icons">
      <div className="grid">
        {data.map((iconKind) => (
          <PlaygroundIconCard icon={iconKind} key={iconKind} />
        ))}
      </div>
    </div>
  );
};
