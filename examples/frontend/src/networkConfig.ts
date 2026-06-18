// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
import { getJsonRpcFullnodeUrl } from '@socialproof/myso/jsonRpc';
import { TESTNET_PACKAGE_ID } from './constants';
import { createNetworkConfig } from '@socialproof/dapp-kit';

const { networkConfig, useNetworkVariable, useNetworkVariables } = createNetworkConfig({
  testnet: {
    network: 'testnet',
    url: getJsonRpcFullnodeUrl('testnet'),
    variables: {
      packageId: TESTNET_PACKAGE_ID,
      mvrName: '@pkg/mydata-demo-1234',
    },
  },
});

export { useNetworkVariable, useNetworkVariables, networkConfig };
