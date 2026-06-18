// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import {
  isWalletOnlySession,
  WALLET_ONLY_ACCESS_TOKEN,
  type MySocialAuth,
  type Session,
} from '@socialproof/mysocial-auth';
import { Ed25519Keypair } from '@socialproof/myso/keypairs/ed25519';
import { getSaltServiceUrl } from './mysocialAuthConfig';

async function sha256First32Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return new Uint8Array(digest).slice(0, 32);
}

function isExplicitWalletOnlySession(session: Session): boolean {
  return session.access_token === WALLET_ONLY_ACCESS_TOKEN;
}

function looksLikeOAuthSession(session: Session): boolean {
  const user = session.user;
  return !!(user?.email || user?.name || (user?.sub && user.sub !== user?.address));
}

async function resolveBearerToken(
  auth: MySocialAuth,
  session: Session,
): Promise<string | undefined> {
  const fromApi = await auth.getAccessTokenForApi();
  if (fromApi) {
    return fromApi;
  }
  if (session.session_access_token) {
    return session.session_access_token;
  }
  if (session.access_token && session.access_token !== WALLET_ONLY_ACCESS_TOKEN) {
    return session.access_token;
  }
  return undefined;
}

async function resolveSalt(session: Session, token: string): Promise<string> {
  if (session.salt) {
    return session.salt;
  }

  const saltResponse = await fetch(getSaltServiceUrl(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });

  if (!saltResponse.ok) {
    throw new Error(`Salt service request failed (${saltResponse.status}).`);
  }

  const { salt } = (await saltResponse.json()) as { salt?: string };
  if (!salt) {
    throw new Error('Salt service returned an invalid response.');
  }

  return salt;
}

function signingUnavailableError(session: Session): Error {
  if (isExplicitWalletOnlySession(session)) {
    return new Error(
      'Signing unavailable — sign in with full MySocial auth (wallet-only sessions cannot sign).',
    );
  }
  if (isWalletOnlySession(session) && looksLikeOAuthSession(session)) {
    return new Error(
      'OAuth session is missing API tokens. Check your allowlisted VITE_MYSOCIAL_AUTH_CLIENT_ID and redirect URI.',
    );
  }
  if (isWalletOnlySession(session)) {
    return new Error(
      'Signing unavailable — sign in with full MySocial auth (wallet-only sessions cannot sign).',
    );
  }
  return new Error('Signing unavailable — no API access token. Sign in with full MySocial auth.');
}

export async function deriveKeypairFromSession(
  auth: MySocialAuth,
  session: Session,
): Promise<Ed25519Keypair> {
  const address = session.user?.address;
  if (!address) {
    throw new Error('Session is missing user address.');
  }

  const token = await resolveBearerToken(auth, session);
  if (!token) {
    throw signingUnavailableError(session);
  }

  const salt = await resolveSalt(session, token);

  const sub = session.sub ?? session.user?.sub ?? session.user?.id;
  if (!sub) {
    throw new Error('Session is missing a stable user identifier for keypair derivation.');
  }

  const seed = await sha256First32Bytes(`${sub}_${salt}`);
  const keypair = Ed25519Keypair.fromSecretKey(seed);

  if (keypair.getPublicKey().toMySoAddress() !== address) {
    throw new Error('Derived keypair address does not match authenticated MySocial address.');
  }

  return keypair;
}
