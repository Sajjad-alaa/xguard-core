import './style.scss';
import { useQuery } from '@tanstack/react-query';
import dayjs from 'dayjs';
import { useEffect, useState } from 'react';
import Skeleton from 'react-loading-skeleton';
import { m } from '../../../../paraglide/messages';
import {
  subscribeCloseModal,
  subscribeOpenModal,
} from '../../../hooks/modalControls/modalsSubjects';
import { ModalName } from '../../../hooks/modalControls/modalTypes';
import type { OpenDevicePostureModal } from '../../../hooks/modalControls/types';
import { getDevicePostureSnapshotQueryOptions } from '../../../query';
import { Badge } from '../../../xguard-ui/components/Badge/Badge';
import { EmptyStateFlexible } from '../../../xguard-ui/components/EmptyStateFlexible/EmptyStateFlexible';
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

const FactValue = ({ value }: { value: string }) => {
  if (value === m.posture_device_fact_yes()) {
    return <Badge variant="success" showIcon icon="check-filled" text={value} />;
  }
  if (value === m.posture_device_fact_no()) {
    return <Badge variant="critical" showIcon icon="cancel" text={value} />;
  }
  if (value === m.posture_device_fact_unknown()) {
    return <Badge variant="neutral" text={value} />;
  }
  return <span className="fact-value-text">{value}</span>;
};

export const DevicePostureContent = ({ deviceId }: OpenDevicePostureModal) => {
  const { data, isPending } = useQuery(getDevicePostureSnapshotQueryOptions(deviceId));

  if (isPending) {
    return (
      <div className="device-posture-loading">
        <Skeleton width={160} height={24} />
        <SizedBox height={ThemeSpacing.Lg} />
        <Skeleton count={5} height={28} />
      </div>
    );
  }

  const snapshot = data?.snapshot;
  if (!snapshot) {
    return (
      <EmptyStateFlexible
        icon="posture-checks"
        title={m.posture_device_modal_never_title()}
        subtitle={m.posture_device_modal_never()}
      />
    );
  }

  return (
    <div className="device-posture">
      <div className="status">
        <Badge
          variant={snapshot.compliant ? 'success' : 'critical'}
          showIcon
          icon={snapshot.compliant ? 'check-filled' : 'warning-filled'}
          text={
            snapshot.compliant
              ? m.posture_device_modal_compliant()
              : m.posture_device_modal_not_compliant()
          }
        />
        <span className="reported">
          {m.posture_device_modal_reported({
            date: dayjs.utc(snapshot.reported_at).local().format('YYYY-MM-DD HH:mm'),
          })}
        </span>
      </div>
      {snapshot.failed_checks.length > 0 && (
        <>
          <SizedBox height={ThemeSpacing.Lg} />
          <p className="title">{m.posture_device_modal_failed()}</p>
          <div className="failed-checks">
            {snapshot.failed_checks.map((check) => (
              <Badge
                key={check}
                variant="critical"
                showIcon
                icon="warning-filled"
                text={check}
              />
            ))}
          </div>
        </>
      )}
      <SizedBox height={ThemeSpacing.Lg} />
      <p className="title">{m.posture_device_modal_facts()}</p>
      <table className="facts-table">
        <thead>
          <tr>
            <th>{m.posture_device_modal_col_property()}</th>
            <th>{m.posture_device_modal_col_value()}</th>
          </tr>
        </thead>
        <tbody>
          {factRows(snapshot.facts).map((row) => (
            <tr key={row.label}>
              <td className="fact-label">{row.label}</td>
              <td>
                <FactValue value={row.value} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <SizedBox height={ThemeSpacing.Lg} />
      <p className="attestation">{m.posture_device_modal_attestation()}</p>
    </div>
  );
};

const ModalContent = DevicePostureContent;
