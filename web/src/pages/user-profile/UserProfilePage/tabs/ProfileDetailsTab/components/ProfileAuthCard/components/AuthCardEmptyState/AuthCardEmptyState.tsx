import './style.scss';
import { Icon } from '../../../../../../../../../shared/xguard-ui/components/Icon';
import { ThemeVariable } from '../../../../../../../../../shared/xguard-ui/types';

type Props = {
  text: string;
  testId?: string;
};

export const AuthCardEmptyState = ({ text, testId }: Props) => {
  return (
    <div className="auth-card-empty-state" data-testid={testId}>
      <Icon icon="cancel" staticColor={ThemeVariable.FgDisabledLight} />
      <p>{text}</p>
    </div>
  );
};
