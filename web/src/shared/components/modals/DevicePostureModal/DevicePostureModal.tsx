import './style.scss';
import { useQuery } from '@tanstack/react-query';
import dayjs from 'dayjs';
import { useEffect, useState } from 'react';
import { m } from '../../../../paraglide/messages';
import {
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../hooks/modalControls/modalTypes';
import type { OpenDevicePostureModal } from '../../../hooks/modalControls/types';
import { getDevicePostureSnapshotQueryOptions } from '../../../query';
import { Badge } from '../../../xguard-ui/components/Badge/Badge';
import { Modal } from '../../../xguard-ui/components/Modal/Modal';
import { SizedBox } from '../../../xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../xguard-ui/types';
import { isPresent } from '../../../xguard-ui/utils/isPresent';
import { factRows } from './facts';

const modalName = ModalName.DevicePosture;

export const DevicePostureModal = () => {
  const [isOpen, setOpen] = useState(false);
  const [modalData, setModalData] = useState<OpenDevicePostureModal | null>(null);

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
      id="device-posture-modal"
      title={m.posture_device_modal_title()}
      isOpen={isOpen}
      onClose={() => setOpen(false)}
      afterClose={() => setModalData(null)}
    >
      {isPresent(modalData) && <ModalContent deviceId={modalData.deviceId} />}
    </Modal>
  );
};

const ModalContent = ({ deviceId }: OpenDevicePostureModal) => {
  const { data } = useQuery(getDevicePostureSnapshotQueryOptions(deviceId));
  if (!data) return null;
  const snapshot = data.snapshot;
  if (!snapshot) {
    return <p className="device-posture-empty">{m.posture_device_modal_never()}</p>;
  }
  return (
    <div className="device-posture">
      <div className="status">
        <Badge
          variant={snapshot.compliant ? 'success' : 'critical'}
          text={
            snapshot.compliant
              ? m.posture_device_modal_compliant()
              : m.posture_device_modal_not_compliant()
          }
        />
        <span>
          {m.posture_device_modal_reported({
            date: dayjs.utc(snapshot.reported_at).local().format('YYYY-MM-DD HH:mm'),
          })}
        </span>
      </div>
      {snapshot.failed_checks.length > 0 && (
        <>
          <SizedBox height={ThemeSpacing.Lg} />
          <p className="title">{m.posture_device_modal_failed()}</p>
          <ul>
            {snapshot.failed_checks.map((check) => (
              <li key={check}>{check}</li>
            ))}
          </ul>
        </>
      )}
      <SizedBox height={ThemeSpacing.Lg} />
      <p className="title">{m.posture_device_modal_facts()}</p>
      <dl>
        {factRows(snapshot.facts).map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>
      <SizedBox height={ThemeSpacing.Lg} />
      <p className="attestation">{m.posture_device_modal_attestation()}</p>
    </div>
  );
};
