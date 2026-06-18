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

export function CreateService() {
  const [price, setPrice] = useState('');
  const [ttl, setTtl] = useState('');
  const [name, setName] = useState('');
  const packageId = useNetworkVariable('packageId');
  const mysoClient = useMySoClient();
  const navigate = useNavigate();
  const { requireKeypair } = useMySocialAuth();

  async function createService(price: number, ttl: number, name: string) {
    if (price === 0 || ttl === 0 || name === '') {
      alert('Please fill in all fields');
      return;
    }
    const ttlMs = ttl * 60 * 1000;
    const tx = new Transaction();
    tx.moveCall({
      target: `${packageId}::subscription::create_service_entry`,
      arguments: [tx.pure.u64(price), tx.pure.u64(ttlMs), tx.pure.string(name)],
    });
    tx.setGasBudget(10000000);
    try {
      const result = await signAndExecuteTransaction(requireKeypair(), mysoClient, tx);
      console.log('res', result);
      const created = (result as { effects?: { created?: { owner?: unknown; reference?: { objectId?: string } }[] } })
        .effects?.created;
      const subscriptionObject = created?.find(
        (item) => item.owner && typeof item.owner === 'object' && 'Shared' in item.owner,
      );
      const createdObjectId = subscriptionObject?.reference?.objectId;
      if (createdObjectId) {
        window.open(
          `${window.location.origin}/subscription-example/admin/service/${createdObjectId}`,
          '_blank',
        );
      }
    } catch (error) {
      console.error(error);
      alert(error instanceof Error ? error.message : 'Failed to create service.');
    }
  }
  const handleViewAll = () => {
    navigate(`/subscription-example/admin/services`);
  };
  return (
    <Card className="max-w-xs">
      <h2 style={{ marginBottom: '1rem' }}>Admin View: Subscription</h2>
      <Flex direction="column" gap="2" justify="start">
        Price in Mist: <input onChange={(e) => setPrice(e.target.value)} />
        Subscription duration in minutes: <input onChange={(e) => setTtl(e.target.value)} />
        Name of the service: <input onChange={(e) => setName(e.target.value)} />
        <Flex direction="row" gap="2" justify="start">
          <Button
            size="3"
            onClick={() => {
              createService(parseInt(price), parseInt(ttl), name);
            }}
          >
            Create Service
          </Button>
          <Button size="3" onClick={handleViewAll}>
            View All Created Services
          </Button>
        </Flex>
      </Flex>
    </Card>
  );
}
