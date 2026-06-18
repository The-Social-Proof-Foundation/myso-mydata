// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import { useContext } from 'react';
import { MySocialAuthContext } from './MySocialAuthProvider';

export function useMySocialAuth() {
  const context = useContext(MySocialAuthContext);
  if (!context) {
    throw new Error('useMySocialAuth must be used within MySocialAuthProvider');
  }
  return context;
}
