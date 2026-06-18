// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';
import {
  isWalletOnlySession,
  type AuthProvider,
  type Session,
} from '@socialproof/mysocial-auth';
import type { Ed25519Keypair } from '@socialproof/myso/keypairs/ed25519';
import { deriveKeypairFromSession } from './deriveKeypair';
import { getMySocialAuth } from './mysocialAuthConfig';

export interface MySocialAuthContextValue {
  session: Session | null;
  address: string | undefined;
  keypair: Ed25519Keypair | null;
  canSign: boolean;
  isWalletOnly: boolean;
  isLoading: boolean;
  authError: string | null;
  signIn: () => void;
  signInWithProvider: (provider: AuthProvider) => void;
  signOut: () => Promise<void>;
  requireKeypair: () => Ed25519Keypair;
}

export const MySocialAuthContext = createContext<MySocialAuthContextValue | null>(null);

export function MySocialAuthProvider({ children }: { children: React.ReactNode }) {
  const auth = useMemo(() => getMySocialAuth(), []);
  const [session, setSession] = useState<Session | null>(null);
  const [keypair, setKeypair] = useState<Ed25519Keypair | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const clearKeypair = useCallback(() => {
    setKeypair(null);
  }, []);

  const hydrateKeypair = useCallback(
    async (nextSession: Session | null) => {
      if (!nextSession) {
        clearKeypair();
        return;
      }

      try {
        const derived = await deriveKeypairFromSession(auth, nextSession);
        setKeypair(derived);
        setAuthError(null);
      } catch (error) {
        clearKeypair();
        setAuthError(error instanceof Error ? error.message : 'Unable to derive signing keypair.');
      }
    },
    [auth, clearKeypair],
  );

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      setIsLoading(true);
      try {
        const existingSession = await auth.getSession();
        if (cancelled) return;
        setSession(existingSession);
        await hydrateKeypair(existingSession);
      } catch (error) {
        if (!cancelled) {
          setAuthError(error instanceof Error ? error.message : 'Unable to restore MySocial session.');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    bootstrap();

    const unsubscribe = auth.onAuthStateChange(async (nextSession) => {
      setSession(nextSession);
      setIsLoading(true);
      await hydrateKeypair(nextSession);
      setIsLoading(false);
    });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [auth, hydrateKeypair]);

  const signInWithProvider = useCallback(
    (provider: AuthProvider) => {
      setAuthError(null);
      auth
        .signIn({ mode: 'popup', provider })
        .then(async (nextSession) => {
          setSession(nextSession);
          await hydrateKeypair(nextSession);
        })
        .catch((error) => {
          setAuthError(error instanceof Error ? error.message : 'MySocial sign-in failed.');
        });
    },
    [auth, hydrateKeypair],
  );

  const signIn = useCallback(() => {
    signInWithProvider('google');
  }, [signInWithProvider]);

  const signOut = useCallback(async () => {
    await auth.signOut();
    setSession(null);
    clearKeypair();
    setAuthError(null);
  }, [auth, clearKeypair]);

  const requireKeypair = useCallback((): Ed25519Keypair => {
    if (!keypair) {
      const message =
        authError ?? 'Signing unavailable — sign in with full MySocial auth to continue.';
      throw new Error(message);
    }
    return keypair;
  }, [authError, keypair]);

  const canSign = keypair !== null;
  const isWalletOnly = session !== null && isWalletOnlySession(session);

  const value = useMemo(
    () => ({
      session,
      address: session?.user?.address,
      keypair,
      canSign,
      isWalletOnly,
      isLoading,
      authError,
      signIn,
      signInWithProvider,
      signOut,
      requireKeypair,
    }),
    [
      session,
      keypair,
      canSign,
      isWalletOnly,
      isLoading,
      authError,
      signIn,
      signInWithProvider,
      signOut,
      requireKeypair,
    ],
  );

  return <MySocialAuthContext.Provider value={value}>{children}</MySocialAuthContext.Provider>;
}
