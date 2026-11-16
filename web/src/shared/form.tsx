import { createFormHook } from '@tanstack/react-form';
import { FormSecretInput } from './components/FormSecretInput/FormSecretInput';
import { FormSelectMultiple } from './components/FormSelectMultiple/FormSelectMultiple';
import { FormUploadField } from './components/FormUploadField/FormUploadField';
import { FormCheckbox } from './xguard-ui/components/form/FormCheckbox/FormCheckbox';
import { FormCheckboxGroup } from './xguard-ui/components/form/FormCheckboxGroup/FormCheckboxGroup';
import { FormDateInput } from './xguard-ui/components/form/FormDateInput/FormDateInput';
import { FormInput } from './xguard-ui/components/form/FormInput/FormInput';
import { FormInteractiveBlock } from './xguard-ui/components/form/FormInteractiveBlock/FormInteractiveBlock';
import { FormMultiSelect } from './xguard-ui/components/form/FormMultiSelect/FormMultiSelect';
import { FormRadio } from './xguard-ui/components/form/FormRadio/FormRadio';
import { FormSelect } from './xguard-ui/components/form/FormSelect/FormSelect';
import { FormSubmitButton } from './xguard-ui/components/form/FormSubmitButton/FormSubmitButton';
import { FormSuggestedIPInput } from './xguard-ui/components/form/FormSuggestedIPInput/FormSuggestedIPInput';
import { FormTextarea } from './xguard-ui/components/form/FormTextarea/FormTextarea';
import { FormToggle } from './xguard-ui/components/form/FormToggle/FormToggle';
import { fieldContext, formContext } from './form-context';

export { useFieldContext, useFormContext } from './form-context';

export const { useAppForm, withFieldGroup, withForm } = createFormHook({
  fieldContext,
  formContext,
  fieldComponents: {
    FormTextarea,
    FormInput,
    FormSelect,
    FormCheckbox,
    FormRadio,
    FormToggle,
    FormSuggestedIPInput,
    FormSelectMultiple,
    FormInteractiveBlock,
    FormUploadField,
    FormCheckboxGroup,
    FormDateInput,
    FormMultiSelect,
    FormSecretInput,
  },
  formComponents: {
    FormSubmitButton,
  },
});
