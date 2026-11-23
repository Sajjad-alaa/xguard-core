import { useNavigate } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import { LocationServiceMode } from '../../../../shared/api/types';
import {
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../../shared/hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../../shared/hooks/modalControls/modalTypes';
import { Modal } from '../../../../shared/xguard-ui/components/Modal/Modal';
import { SectionSelect } from '../../../../shared/xguard-ui/components/SectionSelect/SectionSelect';
import { SizedBox } from '../../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../../shared/xguard-ui/types';
import { useAddLocationStore } from '../../../AddLocationPage/useAddLocationStore';

const modalNameValue = ModalName.AddLocation;

export const AddLocationModal = () => {
  const [isOpen, setOpen] = useState(false);

  useEffect(() => {
    const openSub = subscribeOpenModal(modalNameValue, () => {
      setOpen(true);
    });
    const closeSub = subscribeCloseModal(modalNameValue, () => setOpen(false));
    return () => {
      openSub.unsubscribe();
      closeSub.unsubscribe();
    };
  }, []);

  return (
    <Modal
      title={m.modal_add_location_title()}
      isOpen={isOpen}
      onClose={() => {
        setOpen(false);
      }}
    >
      <AddLocationModalContent />
    </Modal>
  );
};

export const AddLocationModalContent = () => {
  const navigate = useNavigate();

  return (
    <>
      <SectionSelect
        image="location"
        content={m.modal_add_location_regular_content()}
        title={m.modal_add_location_regular_title()}
        data-testid="add-regular-location"
        onClick={() => {
          useAddLocationStore.getState().start();
          navigate({
            to: '/add-location',
          });
        }}
      />
      <SizedBox height={ThemeSpacing.Md} />
      <SectionSelect
        image="service-location"
        content={m.modal_add_location_service_content()}
        title={m.modal_add_location_service_title()}
        data-testid="add-service-location"
        onClick={() => {
          useAddLocationStore.getState().start({
            locationType: 'service',
            service_location_mode: LocationServiceMode.Prelogon,
          });
          setTimeout(() => {
            navigate({
              to: '/add-location',
            });
          }, 100);
        }}
      />
    </>
  );
};
