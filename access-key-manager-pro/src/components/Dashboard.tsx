
import React from 'react';
import { useAuth } from './AuthProvider';
import { LoginForm } from './LoginForm';
import { TokenManager } from './TokenManager';

export const Dashboard: React.FC = () => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  return <TokenManager />;
};
