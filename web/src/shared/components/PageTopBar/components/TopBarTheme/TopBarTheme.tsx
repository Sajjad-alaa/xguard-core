import { useMemo } from 'react';
import { useTheme } from '../../../../hooks/theme/useTheme';
import { IconKind } from '../../../../xguard-ui/components/Icon';
import { IconButtonMenu } from '../../../../xguard-ui/components/IconButtonMenu/IconButtonMenu';
import type { MenuItemsGroup } from '../../../../xguard-ui/components/Menu/types';

export const TopBarTheme = () => {
  const { theme, changeTheme } = useTheme();

  const currentIcon = useMemo(() => {
    switch (theme) {
      case 'dark':
        return IconKind.DarkTheme;
      case 'light':
        return IconKind.LightTheme;
    }
  }, [theme]);

  const menu = useMemo(
    (): MenuItemsGroup[] => [
      {
        items: [
          {
            text: 'Light',
            icon: 'light-theme',
            onClick: () => {
              changeTheme('light');
            },
          },
          {
            text: 'Dark',
            icon: 'dark-theme',
            onClick: () => {
              changeTheme('dark');
            },
          },
        ],
      },
    ],
    [changeTheme],
  );

  return (
    <div className="top-bar-theme">
      <IconButtonMenu icon={currentIcon} menuItems={menu} />
    </div>
  );
};
