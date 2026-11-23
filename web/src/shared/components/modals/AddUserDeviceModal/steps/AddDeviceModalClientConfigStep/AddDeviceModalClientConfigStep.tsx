import { useMemo, useState } from 'react';
import { m } from '../../../../../../paraglide/messages';
import { SizedBox } from '../../../../../xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../../xguard-ui/types';
import { useAddUserDeviceModal } from '../../store/useAddUserDeviceModal';
import './style.scss';
import { useQuery } from '@tanstack/react-query';
import { titleCase } from 'text-case';
import {
  buildClientDownloadLinks,
  linuxDownloadItems,
  mobileDownloadItems,
} from '../../../../../clientDownloads';
import { clientDownloadsQueryOptions } from '../../../../../query';
import { openClientLink } from '../../../../../utils/openVirtualLink';
import { Button } from '../../../../../xguard-ui/components/Button/Button';
import { CopyField } from '../../../../../xguard-ui/components/CopyField/CopyField';
import { Divider } from '../../../../../xguard-ui/components/Divider/Divider';
import { Fold } from '../../../../../xguard-ui/components/Fold/Fold';
import { FoldButton } from '../../../../../xguard-ui/components/FoldButton/FoldButton';
import { IconButton } from '../../../../../xguard-ui/components/IconButton/IconButton';
import { IconButtonMenu } from '../../../../../xguard-ui/components/IconButtonMenu/IconButtonMenu';
import type { MenuItemsGroup } from '../../../../../xguard-ui/components/Menu/types';
import { QrCard } from '../../../../../xguard-ui/components/QrCard/QrCard';
import { ContainerWithIcon } from '../../../../ContainerWithIcon/ContainerWithIcon';
import { Controls } from '../../../../Controls/Controls';

export const AddDeviceModalClientConfigStep = () => {
  const enrollment = useAddUserDeviceModal((s) => s.enrollment);
  const [manualOpen, setManualOpen] = useState(false);
  const { data: clientLinks } = useQuery(clientDownloadsQueryOptions);

  const deepLink = useMemo(() => {
    if (!enrollment) return null;
    return `xguard://addinstance?token=${enrollment.token}&url=${enrollment.url}`;
  }, [enrollment]);

  const qrData = useMemo(() => {
    if (!enrollment) return null;
    return btoa(
      JSON.stringify({
        url: enrollment.url,
        token: enrollment.token,
      }),
    );
  }, [enrollment]);

  const linuxMenu = useMemo((): MenuItemsGroup[] => {
    const links = clientLinks ?? buildClientDownloadLinks();
    return [
      {
        header: {
          text: `${titleCase(m.misc_for())} Linux`,
        },
        items: linuxDownloadItems(links).map((item) => ({
          icon: item.id.startsWith('deb') ? 'ubuntu' : 'linux',
          text: item.label,
          onClick: () => openClientLink(item.href),
        })),
      },
      {
        items: [
          {
            icon: 'linux',
            text: m.client_downloads_all_downloads(),
            onClick: () => openClientLink(links.releases),
          },
        ],
      },
    ];
  }, [clientLinks]);

  const links = clientLinks ?? buildClientDownloadLinks();
  const mobileLinks = mobileDownloadItems(links);

  if (!deepLink || !qrData || !enrollment) return null;

  return (
    <div id="add-device-client-step">
      <header>
        <p>{m.modal_add_user_device_client_title()}</p>
        <p>{m.modal_add_user_device_client_subtitle()}</p>
      </header>
      <SizedBox height={ThemeSpacing.Xl2} />
      <ContainerWithIcon icon="desktop" id="setup-desktop">
        <header>
          <h5>{m.modal_add_user_device_client_desktop_title()}</h5>
          <p>{m.modal_add_user_device_client_desktop_automatic()}</p>
          <p>
            {m.modal_add_user_device_client_desktop_automatic_explain_1()}{' '}
            <span>{m.modal_add_user_device_client_desktop_automatic_explain_2()}</span>
          </p>
        </header>
        <div className="buttons">
          <a href={deepLink} target="_blank" rel="noopener">
            <Button
              text={m.modal_add_user_device_client_desktop_one_click()}
              variant="primary"
              iconRight="open-in-new-window"
            />
          </a>
          <div className="download">
            <p>{m.modal_add_user_device_client_desktop_download()}</p>
            <a
              href={links.windowsX64}
              target="_blank"
              rel="noopener noreferrer"
              title="Windows (x64, .msi)"
              data-testid="download-windows"
            >
              <IconButton icon="windows" />
            </a>
            <a
              href={links.macosUniversal}
              target="_blank"
              rel="noopener noreferrer"
              title="macOS (.dmg)"
              data-testid="download-macos"
            >
              <IconButton icon="apple" />
            </a>
            <IconButtonMenu icon="linux" menuItems={linuxMenu} />
          </div>
        </div>
        <Divider orientation="horizontal" />
        <Fold open={manualOpen} contentClassName="manual">
          <p className="title">{m.modal_add_user_device_client_desktop_manual_title()}</p>
          <p className="subtitle">
            {m.modal_add_user_device_client_desktop_manual_subtitle()}
          </p>
          <SizedBox height={ThemeSpacing.Xl2} />
          <div className="form-col-2">
            <CopyField
              text={enrollment?.url}
              copyTooltip={m.misc_clipboard_copy()}
              label={m.form_label_url()}
            />
            <CopyField
              copyTooltip={m.misc_clipboard_copy()}
              text={enrollment.token}
              label={m.form_label_token()}
            />
          </div>
          <SizedBox height={ThemeSpacing.Xl2} />
        </Fold>
        <FoldButton
          textClose={m.modal_add_user_device_client_fold_open()}
          textOpen={m.modal_add_user_device_client_fold_closed()}
          open={manualOpen}
          onChange={setManualOpen}
        />
      </ContainerWithIcon>
      <SizedBox height={ThemeSpacing.Md} />
      <ContainerWithIcon id="setup-mobile" icon="phone">
        <header>
          <h5>{m.modal_add_user_device_client_mobile_title()}</h5>
          <p>{m.modal_add_user_device_client_mobile_subtitle()}</p>
        </header>
        <div className="bottom">
          <div className="qr">
            <QrCard value={qrData} />
          </div>
          {mobileLinks.length > 0 && (
            <div className="download">
              <p>{m.modal_add_user_device_client_mobile_get_mobile()}</p>
              <div className="links">
                {mobileLinks.map((item) => (
                  <a
                    key={item.id}
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid={`download-${item.id}`}
                  >
                    <Button
                      variant="outlined"
                      iconLeft={item.id === 'android' ? 'android' : 'apple'}
                      text={item.label}
                    />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      </ContainerWithIcon>
      <Controls>
        <div className="left">
          <p>{`Once your XGuard client is configured, you can close this window.`}</p>
        </div>
        <div className="right">
          <Button
            text={m.controls_close()}
            onClick={() => {
              useAddUserDeviceModal.getState().close();
            }}
          />
        </div>
      </Controls>
    </div>
  );
};
