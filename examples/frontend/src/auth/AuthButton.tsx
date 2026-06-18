// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import { Button, Flex, Text } from '@radix-ui/themes';
import { useMySocialAuth } from './useMySocialAuth';

function truncateAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function AuthButton() {
  const { address, canSign, isLoading, authError, signIn, signInWithProvider, signOut } =
    useMySocialAuth();

  if (isLoading) {
    return <Text size="2">Loading session...</Text>;
  }

  if (address && canSign) {
    return (
      <Flex align="center" gap="2">
        <Text size="2">{truncateAddress(address)}</Text>
        <Button variant="soft" onClick={() => void signOut()}>
          Sign out
        </Button>
      </Flex>
    );
  }

  if (address && !canSign) {
    return (
      <Flex direction="column" align="end" gap="1">
        <Flex align="center" gap="2">
          <Text size="2">{truncateAddress(address)}</Text>
          <Button
            onClick={() => {
              void signOut().then(() => signInWithProvider('google'));
            }}
          >
            Sign in again
          </Button>
        </Flex>
        {authError && (
          <Text size="1" color="red" style={{ maxWidth: '20rem', textAlign: 'right' }}>
            {authError}
          </Text>
        )}
      </Flex>
    );
  }

  return (
    <Flex direction="column" align="end" gap="1">
      <Flex gap="2">
        <Button onClick={signIn}>Sign in with Google</Button>
        <Button variant="soft" onClick={() => signInWithProvider('none')}>
          Other options
        </Button>
      </Flex>
      {authError && (
        <Text size="1" color="red">
          {authError}
        </Text>
      )}
    </Flex>
  );
}
