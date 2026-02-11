// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { useSignPersonalMessage, useMySoClient } from '@socialproof/dapp-kit';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex, Grid } from '@radix-ui/themes';
import { fromHex } from '@socialproof/myso/utils';
import { Transaction } from '@socialproof/myso/transactions';
import {
  KeyServerConfig,
  MyDataClient,
  SessionKey,
  type ExportedSessionKey
} from '@socialproof/mydata';
import { useParams } from 'react-router-dom';
import { downloadAndDecrypt, getObjectExplorerLink, MoveCallConstructor } from './utils';
import { set, get } from 'idb-keyval';
import { getFullnodeUrl, MySoClient } from '@socialproof/myso/client';

const TTL_MIN = 10;
export interface FeedData {
  allowlistId: string;
  allowlistName: string;
  blobIds: string[];
}

function constructMoveCall(packageId: string, allowlistId: string): MoveCallConstructor {
  return (tx: Transaction, id: string) => {
    tx.moveCall({
      target: `${packageId}::allowlist::mydata_approve`,
      arguments: [tx.pure.vector('u8', fromHex(id)), tx.object(allowlistId)],
    });
  };
}

const Feeds: React.FC<{ mysoAddress: string }> = ({ mysoAddress }) => {
  const mysoClient = useMySoClient();
  const serverObjectIds = ["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"];
  const client = new MyDataClient({
    mysoClient,
    serverConfigs: serverObjectIds.map((id) => ({
      objectId: id,
      weight: 1,
    })),
    verifyKeyServers: false,
  });
  const packageId = useNetworkVariable('packageId');
  const mvrName = useNetworkVariable('mvrName');

  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const { id } = useParams();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const { mutate: signPersonalMessage } = useSignPersonalMessage();

  useEffect(() => {
    // Call getFeed immediately
    getFeed();

    // Set up interval to call getFeed every 3 seconds
    const intervalId = setInterval(() => {
      getFeed();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
  }, [id, mysoClient, packageId]); // Add all dependencies that getFeed uses

  async function getFeed() {
    const allowlist = await mysoClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    const encryptedObjects = await mysoClient
      .getDynamicFields({
        parentId: id!,
      })
      .then((res: { data: any[] }) => res.data.map((obj) => obj.name.value as string));
    const fields = (allowlist.data?.content as { fields: any })?.fields || {};
    const feedData = {
      allowlistId: id!,
      allowlistName: fields?.name,
      blobIds: encryptedObjects,
    };
    setFeed(feedData);
  }

  const onView = async (blobIds: string[], allowlistId: string) => {
    const imported: ExportedSessionKey = await get('sessionKey');

    if (imported) {
      try {
        const currentSessionKey = await SessionKey.import(
          imported,
          new MySoClient({ url: getFullnodeUrl('testnet') }),
        );
        console.log('loaded currentSessionKey', currentSessionKey);
        if (
          currentSessionKey &&
          !currentSessionKey.isExpired() &&
          currentSessionKey.getAddress() === mysoAddress
        ) {
          const moveCallConstructor = constructMoveCall(packageId, allowlistId);
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
      } catch (error) {
        console.log('Imported session key is expired', error);
      }
    }

    set('sessionKey', null);

    const sessionKey = await SessionKey.create({
      address: mysoAddress,
      packageId,
      ttlMin: TTL_MIN,
      mysoClient,
      mvrName,
    });

    try {
      signPersonalMessage(
        {
          message: sessionKey.getPersonalMessage(),
        },
        {
          onSuccess: async (result: { signature: string }) => {
            await sessionKey.setPersonalMessageSignature(result.signature);
            const moveCallConstructor = await constructMoveCall(packageId, allowlistId);
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
            set('sessionKey', sessionKey.export());
          },
        },
      );
    } catch (error: any) {
      console.error('Error:', error);
    }
  };

  return (
    <Card>
      <h2 style={{ marginBottom: '1rem' }}>
        Files for Allowlist {feed?.allowlistName} (ID{' '}
        {feed?.allowlistId && getObjectExplorerLink(feed.allowlistId)})
      </h2>
      {feed === undefined ? (
        <p>No files found for this allowlist.</p>
      ) : (
        <Grid columns="2" gap="3">
          <Card key={feed!.allowlistId}>
            <Flex direction="column" align="start" gap="2">
              {feed!.blobIds.length === 0 ? (
                <p>No files found for this allowlist.</p>
              ) : (
                <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                  <Dialog.Trigger>
                    <Button onClick={() => onView(feed!.blobIds, feed!.allowlistId)}>
                      Download And Decrypt All Files
                    </Button>
                  </Dialog.Trigger>
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
        </Grid>
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

export default Feeds;
