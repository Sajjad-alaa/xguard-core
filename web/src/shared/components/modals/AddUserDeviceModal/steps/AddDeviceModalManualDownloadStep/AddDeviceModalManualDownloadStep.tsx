import { m } from '../../../../../../paraglide/messages';
import { Divider } from '../../../../../xguard-ui/components/Divider/Divider';
import { IconKind } from '../../../../../xguard-ui/components/Icon';
import { InfoBanner } from '../../../../../xguard-ui/components/InfoBanner/InfoBanner';
import { ModalControls } from '../../../../../xguard-ui/components/ModalControls/ModalControls';
import { useAddUserDeviceModal } from '../../store/useAddUserDeviceModal';
import './style.scss';
import { isPresent } from '../../../../../xguard-ui/utils/isPresent';
import { ModalDeviceConfigSection } from '../../../../ModalDeviceConfigSection/ModalDeviceConfigSection';

export const AddDeviceModalManualDownloadStep = () => {
  const response = useAddUserDeviceModal((s) => s.createDeviceResponse);
  const keys = useAddUserDeviceModal((s) => s.manualConfig);
  if (!isPresent(response) || !isPresent(keys))
    throw new Error('Required store data not present during render');

  return (
    <div id="add-user-device-manual-download">
      <InfoBanner
        variant="warning"
        icon={IconKind.WarningOutlined}
        text={m.modal_network_device_manual_config_warning()}
      />
      <Divider orientation="horizontal" />
      <ModalDeviceConfigSection data={response} privateKey={keys.privateKey} />
      <Divider />
      <ModalControls
        submitProps={{
          text: m.controls_complete(),
          onClick: () => {
            useAddUserDeviceModal.getState().close();
          },
        }}
      />
    </div>
  );
};
