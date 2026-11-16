import { m } from '../../../../../paraglide/messages';
import { Controls } from '../../../../../shared/components/Controls/Controls';
import { Button } from '../../../../../shared/xguard-ui/components/Button/Button';
import { CodeCard } from '../../../../../shared/xguard-ui/components/CodeCard/CodeCard';
import { Modal } from '../../../../../shared/xguard-ui/components/Modal/Modal';

type Props = {
  isOpen: boolean;
  error: string;
  onClose: () => void;
};

export const LdapConnectionErrorModal = ({ isOpen, error, onClose }: Props) => (
  <Modal
    title={m.modal_ldap_connection_error_title()}
    size="primary"
    isOpen={isOpen}
    onClose={onClose}
  >
    <CodeCard
      title={m.modal_ldap_connection_error_code_title()}
      value={error}
      copy
      download
    />
    <Controls>
      <div className="right">
        <Button text={m.controls_close()} onClick={onClose} />
      </div>
    </Controls>
  </Modal>
);
