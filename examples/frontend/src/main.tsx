// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import ReactDOM from 'react-dom/client';
import '@socialproof/dapp-kit/dist/index.css';
import '@radix-ui/themes/styles.css';

import { MySoClientProvider, WalletProvider } from '@socialproof/dapp-kit';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Theme } from '@radix-ui/themes';
import App from './App';
import { networkConfig } from './networkConfig';

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Theme appearance="dark">
      <QueryClientProvider client={queryClient}>
        <MySoClientProvider networks={networkConfig} defaultNetwork="testnet">
          <WalletProvider autoConnect>
            <App />
          </WalletProvider>
        </MySoClientProvider>
      </QueryClientProvider>
    </Theme>
  </React.StrictMode>,
);
