// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
import { getFullnodeUrl } from '@socialproof/myso/client';
import { TESTNET_PACKAGE_ID } from './constants';
import { createNetworkConfig } from '@socialproof/dapp-kit';

const { networkConfig, useNetworkVariable, useNetworkVariables } = createNetworkConfig({
  testnet: {
    url: getFullnodeUrl('testnet'),
    variables: {
      packageId: TESTNET_PACKAGE_ID,
      mvrName: '@pkg/mydata-demo-1234',
    },
  },
});

export { useNetworkVariable, useNetworkVariables, networkConfig };
