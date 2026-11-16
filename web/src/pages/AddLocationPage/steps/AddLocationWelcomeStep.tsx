import { m } from '../../../paraglide/messages';
import { Controls } from '../../../shared/components/Controls/Controls';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { useAddLocationStore } from '../useAddLocationStore';

export const AddLocationWelcomeStep = () => {
  return (
    <>
      <Divider spacing={ThemeSpacing.Xl2} />
      <Controls>
        <Button
          variant="primary"
          text={m.add_location_page_title()}
          onClick={() => {
            useAddLocationStore.setState({
              isWelcome: false,
            });
          }}
        />
      </Controls>
    </>
  );
};
