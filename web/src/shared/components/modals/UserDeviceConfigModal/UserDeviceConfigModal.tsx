import { m } from '../../../../paraglide/messages';
import type { AddDeviceResponse } from '../../../api/types';
import { Divider } from '../../../xguard-ui/components/Divider/Divider';
import { IconKind } from '../../../xguard-ui/components/Icon';
import { InfoBanner } from '../../../xguard-ui/components/InfoBanner/InfoBanner';
import { Modal } from '../../../xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../../xguard-ui/components/ModalControls/ModalControls';
import { isPresent } from '../../../xguard-ui/utils/isPresent';
import {
  closeModal,
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../hooks/modalControls/modalTypes';
import { ModalDeviceConfigSection } from '../../ModalDeviceConfigSection/ModalDeviceConfigSection';
import './style.scss';
import { useEffect, useState } from 'react';

const modalName = ModalName.UserDeviceConfig;

export const UserDeviceConfigModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<AddDeviceResponse | null>(null);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalName, (data) => {
      setModalData(data);
      setOpen(true);
    });
    const closeSub = subscribeCloseModal(modalName, () => setOpen(false));
    return () => {
      openSub.unsubscribe();
      closeSub.unsubscribe();
    };
  }, []);

  return (
    <Modal
      id="user-device-config-modal"
      title={m.modal_user_device_config_title()}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => {
        setModalData(null);
      }}
    >
      {isPresent(modalData) && <ModalContent data={modalData} />}
    </Modal>
  );
};

const ModalContent = ({ data }: { data: AddDeviceResponse }) => {
  return (
    <>
      <InfoBanner
        variant="warning"
        icon={IconKind.WarningOutlined}
        text={m.modal_user_device_config_warning()}
      />
      <Divider orientation="horizontal" />
      <ModalDeviceConfigSection data={data} />
      <Divider />
      <ModalControls
        submitProps={{
          text: m.controls_close(),
          onClick: () => {
            closeModal(modalName);
          },
        }}
      />
    </>
  );
};
