import type { HTMLProps, PropsWithChildren } from 'react';
import './style.scss';
import clsx from 'clsx';
import { SizedBox } from '../../xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../xguard-ui/types';
import { isPresent } from '../../xguard-ui/utils/isPresent';

type Props = HTMLProps<HTMLDivElement> &
  PropsWithChildren & {
    title?: string;
  };

export const DescriptionBlock = ({
  children,
  className,
  title,
  ...containerProps
}: Props) => {
  return (
    <div className={clsx('description-block', className)} {...containerProps}>
      {isPresent(title) && (
        <>
          <p className="title">{title}</p>
          <SizedBox height={ThemeSpacing.Xs} />
        </>
      )}
      <div>{children}</div>
    </div>
  );
};
