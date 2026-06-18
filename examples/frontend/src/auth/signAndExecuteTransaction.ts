// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

import type { Ed25519Keypair } from '@socialproof/myso/keypairs/ed25519';
import type { MySoJsonRpcClient } from '@socialproof/myso/jsonRpc';
import type { Transaction } from '@socialproof/myso/transactions';

export async function signAndExecuteTransaction(
  keypair: Ed25519Keypair,
  mysoClient: MySoJsonRpcClient,
  transaction: Transaction,
) {
  return keypair.signAndExecuteTransaction({ transaction, client: mysoClient });
}
