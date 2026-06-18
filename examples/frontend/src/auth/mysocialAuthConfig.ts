// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import { createMySocialAuth, type MySocialAuth } from '@socialproof/mysocial-auth';

function requireEnv(name: string): string {
  const value = import.meta.env[name];
  if (!value) {
    throw new Error(
      `Missing ${name}. Copy .env.example to .env.local and set your MySocial Auth credentials.`,
    );
  }
  return value;
}

let authInstance: MySocialAuth | null = null;

export function getMySocialAuth(): MySocialAuth {
  if (!authInstance) {
    authInstance = createMySocialAuth({
      apiBaseUrl: requireEnv('VITE_MYSOCIAL_AUTH_API_BASE_URL'),
      authOrigin: requireEnv('VITE_MYSOCIAL_AUTH_ORIGIN'),
      clientId: requireEnv('VITE_MYSOCIAL_AUTH_CLIENT_ID'),
      redirectUri: requireEnv('VITE_MYSOCIAL_AUTH_REDIRECT_URI'),
      storage: 'session',
    });
  }
  return authInstance;
}

export function getSaltServiceUrl(): string {
  return requireEnv('VITE_MYSOCIAL_SALT_URL');
}
