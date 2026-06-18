# Examples

This reference application includes two different functionalities to showcase MyData's capabilities:

**Allowlist-Based Access**

An allowlist enables a creator to manage a set of authorized addresses by adding or removing members as needed. The creator can associate encrypted files with the allowlist, ensuring that only designated members can access the content.

To gain access, a user must sign a personal message, which is then verified against the allowlist. Upon successful verification, the user retrieves two key shares from two independent servers. If the membership check is validated, the user combines these key shares to derive the decryption key, which allows them to access and view the decrypted content.

**Subscription-Based Access**

A subscription service allows a creator to define a service with a specified price (denominated in MIST) and a time period (X minutes). When a user purchases a subscription, it is represented as a non-fungible token (NFT) stored on-chain.

To access the service, the user must sign a personal message, which is then validated by the servers. The servers verify whether the subscription is active for the next X minutes by referencing the on-chain MySo clock and ensuring the user holds a valid subscription NFT. If the conditions are met, the user retrieves the decryption key, enabling access to the decrypted content.

> **IMPORTANT**
> This reference application serves as a demonstration of MyData's capabilities and is intended solely as a playground environment. It does not provide guarantees of uptime, reliability, or correctness. Users are strongly advised not to sign in with primary accounts or upload any sensitive content while utilizing this application.
>
> By accessing and using this reference application, you acknowledge and accept the inherent risks associated with cryptographic and blockchain-based systems. You confirm that you possess a working knowledge of Digital Assets and understand the implications of their usage.
>
> You further acknowledge that you are solely responsible for all actions taken within this application, including but not limited to signing in with MySocial, adding content, or providing approvals or permissions by cryptographically signing blockchain messages or transactions.
>
> Mysten Labs, Inc., along with its affiliates and employees, assumes no responsibility for the security, integrity, or compliance of any content added or actions performed within this reference application. Users must exercise caution and use this application at their own risk.

## Run locally

1. Copy the auth environment template and fill in your registered MySocial Auth credentials:

```bash
cd frontend
cp .env.example .env.local
```

Required variables in `.env.local`:

- `VITE_MYSOCIAL_AUTH_CLIENT_ID` — your **allowlisted** platform client ID (placeholder values like `your-platform-id` will not return API tokens needed for signing)
- `VITE_MYSOCIAL_AUTH_REDIRECT_URI` — your allowlisted callback URL (required even for popup login). For local dev use `http://localhost:5173/auth/callback`
- `VITE_MYSOCIAL_AUTH_API_BASE_URL` — e.g. `https://api.testnet.mysocial.network`
- `VITE_MYSOCIAL_AUTH_ORIGIN` — e.g. `https://auth.testnet.mysocial.network`
- `VITE_MYSOCIAL_SALT_URL` — e.g. `https://salt.testnet.mysocial.network/salt`

2. Install dependencies and start the dev server:

```bash
pnpm install
pnpm dev
```

3. Open the app and click **Sign in with Google** (popup OAuth login). Fund your authenticated testnet address from [faucet.mysocial.network](https://faucet.mysocial.network/) before sending transactions.

### Troubleshooting: "Signed in but signing unavailable"

If you see an address in the header but cannot create allowlists or decrypt files:

1. Verify `VITE_MYSOCIAL_AUTH_CLIENT_ID` is a **real allowlisted** client ID, not a placeholder.
2. Verify `VITE_MYSOCIAL_AUTH_REDIRECT_URI` exactly matches an allowlisted callback (including `http://localhost:5173/auth/callback` for local dev).
3. Sign out and sign in again after updating `.env.local`, then restart the dev server.
4. Use **Sign in with Google** (OAuth). Create/Import Wallet sessions cannot sign transactions in this demo.
5. After OAuth sign-in, the auth popup should return `session_access_token` or `refresh_token`. If those are missing, the client ID or redirect URI is likely misconfigured server-side.
