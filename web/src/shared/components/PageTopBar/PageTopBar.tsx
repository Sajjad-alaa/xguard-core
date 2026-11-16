import { Divider } from '../../xguard-ui/components/Divider/Divider';
import './style.scss';
import { useApp } from '../../hooks/useApp';
import { useAuth } from '../../hooks/useAuth';
import { IconButton } from '../../xguard-ui/components/IconButton/IconButton';
import { SizedBox } from '../../xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../xguard-ui/types';
import { TopBarProfile } from './components/TopBarProfile/TopBarProfile';
import { TopBarTheme } from './components/TopBarTheme/TopBarTheme';

type Props = {
  title: string;
  navOpen: boolean;
};

export const PageTopBar = ({ title, navOpen }: Props) => {
  const isAdmin = useAuth((s) => s.isAdmin);
  return (
    <div className="page-top-bar">
      {!navOpen && isAdmin && (
        <>
          <IconButton
            onClick={() => {
              useApp.setState({
                navigationOpen: true,
              });
            }}
            icon="hamburger"
          />
          <SizedBox height={1} width={ThemeSpacing.Xl} />
        </>
      )}
      <p className="page-title">{title}</p>
      <div className="right">
        <Divider orientation="vertical" />
        <TopBarProfile />
        <Divider orientation="vertical" />
        <TopBarTheme />
      </div>
    </div>
  );
};
