import { createFileRoute } from '@tanstack/react-router';
import { LoginRadius } from '../../../pages/auth/LoginRadius/LoginRadius';

export const Route = createFileRoute('/auth/mfa/radius')({
  component: LoginRadius,
});
