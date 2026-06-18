// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import { Transaction } from '@socialproof/myso/transactions';
import { Button, Card, Flex } from '@radix-ui/themes';
import { useMySoClient } from '@socialproof/dapp-kit';
import { useState } from 'react';
import { useNetworkVariable } from './networkConfig';
import { useNavigate } from 'react-router-dom';
import { useMySocialAuth } from './auth/useMySocialAuth';
import { signAndExecuteTransaction } from './auth/signAndExecuteTransaction';

export function CreateAllowlist() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const packageId = useNetworkVariable('packageId');
  const mysoClient = useMySoClient();
  const { requireKeypair } = useMySocialAuth();

  async function createAllowlist(name: string) {
    if (name === '') {
      alert('Please enter a name for the allowlist');
      return;
    }
    const tx = new Transaction();
    tx.moveCall({
      target: `${packageId}::allowlist::create_allowlist_entry`,
      arguments: [tx.pure.string(name)],
    });
    tx.setGasBudget(10000000);
    try {
      const result = await signAndExecuteTransaction(requireKeypair(), mysoClient, tx);
      console.log('res', result);
      const created = (result as { effects?: { created?: { owner?: unknown; reference?: { objectId?: string } }[] } })
        .effects?.created;
      const allowlistObject = created?.find(
        (item) => item.owner && typeof item.owner === 'object' && 'Shared' in item.owner,
      );
      const createdObjectId = allowlistObject?.reference?.objectId;
      if (createdObjectId) {
        window.open(
          `${window.location.origin}/allowlist-example/admin/allowlist/${createdObjectId}`,
          '_blank',
        );
      }
    } catch (error) {
      console.error(error);
      alert(error instanceof Error ? error.message : 'Failed to create allowlist.');
    }
  }

  const handleViewAll = () => {
    navigate(`/allowlist-example/admin/allowlists`);
  };

  return (
    <Card>
      <h2 style={{ marginBottom: '1rem' }}>Admin View: Allowlist</h2>
      <Flex direction="row" gap="2" justify="start">
        <input placeholder="Allowlist Name" onChange={(e) => setName(e.target.value)} />
        <Button
          size="3"
          onClick={() => {
            createAllowlist(name);
          }}
        >
          Create Allowlist
        </Button>
        <Button size="3" onClick={handleViewAll}>
          View All Created Allowlists
        </Button>
      </Flex>
    </Card>
  );
}
