import './style.scss';
import { IconButton } from '../../../../xguard-ui/components/IconButton/IconButton';
import { ModalFoundation } from '../../../../xguard-ui/components/ModalFoundation/ModalFoundation';
import type { PlayableVideo } from '../../../types';
import { VideoPlayer } from '../../VideoPlayer/VideoPlayer';

export interface VideoOverlayProps {
  video: PlayableVideo | null;
  isOpen: boolean;
  onClose: () => void;
  afterClose: () => void;
}

export const VideoOverlay = ({
  video,
  isOpen,
  onClose,
  afterClose,
}: VideoOverlayProps) => {
  return (
    <ModalFoundation
      isOpen={isOpen}
      contentClassName="video-support-modal-container"
      afterClose={afterClose}
    >
      {video && (
        <>
          <IconButton
            icon="close"
            className="video-support-modal-container-close"
            onClick={onClose}
          />
          <div className="video-support-modal">
            <VideoPlayer video={video} errorVariant="overlay" />
          </div>
        </>
      )}
    </ModalFoundation>
  );
};
