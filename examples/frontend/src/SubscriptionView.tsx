// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { useMySoClient } from '@socialproof/dapp-kit';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex } from '@radix-ui/themes';
import { coinWithBalance, Transaction } from '@socialproof/myso/transactions';
import { fromHex, MYSO_CLOCK_OBJECT_ID } from '@socialproof/myso/utils';
import { MyDataClient, SessionKey } from '@socialproof/mydata';
import { useParams } from 'react-router-dom';
import { downloadAndDecrypt, getObjectExplorerLink, MoveCallConstructor } from './utils';
import { useMySocialAuth } from './auth/useMySocialAuth';
import { signAndExecuteTransaction } from './auth/signAndExecuteTransaction';

const TTL_MIN = 10;
export interface FeedData {
  id: string;
  fee: string;
  ttl: string;
  owner: string;
  name: string;
  blobIds: string[];
  subscriptionId?: string;
}

const FeedsToSubscribe: React.FC<{ mysoAddress: string }> = ({ mysoAddress }) => {
  const mysoClient = useMySoClient();
  const { keypair, requireKeypair } = useMySocialAuth();
  const { id } = useParams();
  const serverObjectIds = ["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"];

  const client = new MyDataClient({
    mysoClient,
    serverConfigs: serverObjectIds.map((id) => ({
      objectId: id,
      weight: 1,
    })),
    verifyKeyServers: false,
  });
  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const packageId = useNetworkVariable('packageId');
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  useEffect(() => {
    getFeed();

    const intervalId = setInterval(() => {
      getFeed();
    }, 3000);

    return () => clearInterval(intervalId);
  }, [id, mysoAddress, packageId, mysoClient]);

  async function getFeed() {
    const encryptedObjects = await mysoClient
      .getDynamicFields({
        parentId: id!,
      })
      .then((res) => res.data.map((obj) => obj.name.value as string));

    const service = await mysoClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    const service_fields = (service.data?.content as { fields: any })?.fields || {};

    const res = await mysoClient.getOwnedObjects({
      owner: mysoAddress,
      options: {
        showContent: true,
        showType: true,
      },
      filter: {
        StructType: `${packageId}::subscription::Subscription`,
      },
    });

    const clock = await mysoClient.getObject({
      id: '0x6',
      options: { showContent: true },
    });
    const fields = (clock.data?.content as { fields: any })?.fields || {};
    const current_ms = fields.timestamp_ms;

    const valid_subscription = res.data
      .map((obj) => {
        const itemFields = (obj!.data!.content as { fields: any }).fields;
        const x = {
          id: itemFields?.id.id,
          created_at: parseInt(itemFields?.created_at),
          service_id: itemFields?.service_id,
        };
        return x;
      })
      .filter((item) => item.service_id === service_fields.id.id)
      .find((item) => {
        return item.created_at + parseInt(service_fields.ttl) > current_ms;
      });

    const nextFeed = {
      ...service_fields,
      id: service_fields.id.id,
      blobIds: encryptedObjects,
      subscriptionId: valid_subscription?.id,
    } as FeedData;
    setFeed(nextFeed);
  }

  function constructMoveCall(
    packageId: string,
    serviceId: string,
    subscriptionId: string,
  ): MoveCallConstructor {
    return (tx: Transaction, id: string) => {
      tx.moveCall({
        target: `${packageId}::subscription::mydata_approve`,
        arguments: [
          tx.pure.vector('u8', fromHex(id)),
          tx.object(subscriptionId),
          tx.object(serviceId),
          tx.object(MYSO_CLOCK_OBJECT_ID),
        ],
      });
    };
  }

  async function handleSubscribe(serviceId: string, fee: number) {
    try {
      const signer = requireKeypair();
      const tx = new Transaction();
      tx.setGasBudget(10000000);
      tx.setSender(mysoAddress);
      const subscription = tx.moveCall({
        target: `${packageId}::subscription::subscribe`,
        arguments: [
          coinWithBalance({
            balance: BigInt(fee),
          }),
          tx.object(serviceId),
          tx.object(MYSO_CLOCK_OBJECT_ID),
        ],
      });
      tx.moveCall({
        target: `${packageId}::subscription::transfer`,
        arguments: [tx.object(subscription), tx.pure.address(mysoAddress)],
      });

      const result = await signAndExecuteTransaction(signer, mysoClient, tx);
      console.log('res', result);
      getFeed();
    } catch (subscribeError) {
      console.error(subscribeError);
      setError(subscribeError instanceof Error ? subscribeError.message : 'Failed to subscribe.');
    }
  }

  const onView = async (
    blobIds: string[],
    serviceId: string,
    fee: number,
    subscriptionId?: string,
  ) => {
    if (!subscriptionId) {
      return handleSubscribe(serviceId, fee);
    }

    try {
      const signer = requireKeypair();

      if (
        currentSessionKey &&
        !currentSessionKey.isExpired() &&
        currentSessionKey.getAddress() === mysoAddress
      ) {
        const moveCallConstructor = constructMoveCall(packageId, serviceId, subscriptionId);
        downloadAndDecrypt(
          blobIds,
          currentSessionKey,
          mysoClient,
          client,
          moveCallConstructor,
          setError,
          setDecryptedFileUrls,
          setIsDialogOpen,
          setReloadKey,
        );
        return;
      }
      setCurrentSessionKey(null);

      const sessionKey = await SessionKey.create({
        address: mysoAddress,
        packageId,
        ttlMin: TTL_MIN,
        mysoClient,
        signer,
      });
      await sessionKey.getCertificate();

      const moveCallConstructor = constructMoveCall(packageId, serviceId, subscriptionId);
      await downloadAndDecrypt(
        blobIds,
        sessionKey,
        mysoClient,
        client,
        moveCallConstructor,
        setError,
        setDecryptedFileUrls,
        setIsDialogOpen,
        setReloadKey,
      );
      setCurrentSessionKey(sessionKey);
    } catch (viewError) {
      console.error('Error:', viewError);
      setError(viewError instanceof Error ? viewError.message : 'Unable to decrypt files.');
    }
  };

  return (
    <Card>
      {feed === undefined ? (
        <p>Waiting for files...</p>
      ) : (
        <Card key={feed!.id}>
          <h2 style={{ marginBottom: '1rem' }}>
            Files for subscription service {feed!.name} (ID {getObjectExplorerLink(feed!.id)})
          </h2>
          <Flex direction="column" gap="2">
            {feed!.blobIds.length === 0 ? (
              <p>No Files yet.</p>
            ) : (
              <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                  <Dialog.Trigger>
                    <Button
                      disabled={!keypair}
                      onClick={() =>
                        onView(feed!.blobIds, feed!.id, Number(feed!.fee), feed!.subscriptionId)
                      }
                    >
                      {feed!.subscriptionId ? (
                        <div>Download And Decrypt All Files</div>
                      ) : (
                        <div>
                          Subscribe for {feed!.fee} MIST for{' '}
                          {Math.floor(parseInt(feed!.ttl) / 60 / 1000)} minutes
                        </div>
                      )}
                    </Button>
                  </Dialog.Trigger>
                </div>
                {decryptedFileUrls.length > 0 && (
                  <Dialog.Content maxWidth="450px" key={reloadKey}>
                    <Dialog.Title>View all files retrieved from Walrus</Dialog.Title>
                    <Flex direction="column" gap="2">
                      {decryptedFileUrls.map((decryptedFileUrl, index) => (
                        <div key={index}>
                          <img src={decryptedFileUrl} alt={`Decrypted image ${index + 1}`} />
                        </div>
                      ))}
                    </Flex>
                    <Flex gap="3" mt="4" justify="end">
                      <Dialog.Close>
                        <Button
                          variant="soft"
                          color="gray"
                          onClick={() => setDecryptedFileUrls([])}
                        >
                          Close
                        </Button>
                      </Dialog.Close>
                    </Flex>
                  </Dialog.Content>
                )}
              </Dialog.Root>
            )}
          </Flex>
        </Card>
      )}
      <AlertDialog.Root open={!!error} onOpenChange={() => setError(null)}>
        <AlertDialog.Content maxWidth="450px">
          <AlertDialog.Title>Error</AlertDialog.Title>
          <AlertDialog.Description size="2">{error}</AlertDialog.Description>

          <Flex gap="3" mt="4" justify="end">
            <AlertDialog.Action>
              <Button variant="solid" color="gray" onClick={() => setError(null)}>
                Close
              </Button>
            </AlertDialog.Action>
          </Flex>
        </AlertDialog.Content>
      </AlertDialog.Root>
    </Card>
  );
};

export default FeedsToSubscribe;
