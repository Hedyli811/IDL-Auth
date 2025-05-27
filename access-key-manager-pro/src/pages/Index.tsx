
import React from 'react';
import { AuthProvider } from '@/components/AuthProvider';
import { Dashboard } from '@/components/Dashboard';

const Index = () => {
  return (
    <AuthProvider>
      <Dashboard />
    </AuthProvider>
  );
};

export default Index;
