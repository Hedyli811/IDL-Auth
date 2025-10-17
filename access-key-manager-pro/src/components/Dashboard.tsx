
import React from 'react';
import { useAuth } from './AuthProvider';
import { LoginForm } from './LoginForm';
import { TokenManager } from './TokenManager';
import { PasswordChangeForm } from './PasswordChangeForm';

export const Dashboard: React.FC = () => {
  const { isAuthenticated, needsPasswordChange } = useAuth();

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  if (needsPasswordChange) {
    return <PasswordChangeForm isRequired={true} />;
  }

  return <TokenManager />;
};
