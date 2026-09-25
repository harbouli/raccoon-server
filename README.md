# Raccoon signaling server

Standalone Node.js/Express server for the sibling RaccoonChat mobile app. It handles short-ID registration, signed connection requests, automatic 32-byte pair-token issuance, fprot WebSocket signaling, and an optional encrypted-frame relay when direct TCP cannot connect. The server forwards ciphertext; it does not have the session decryption keys.

## Run locally

```sh
npm install
npm start
```

`GET /health` is available on port 8787. Optional environment variables: `RACCOON_HOST` (default `0.0.0.0` when started via npm), `RACCOON_PORT` (default `8787`), and `RACCOON_ACCOUNT_FILE` (default `data/accounts.json`). The accounts file is private to this server and ignored by Git.

## Deployment

Point the app's `src/config.ts` at `https://raccoon.harbouli.dev` (WebSocket signaling and encrypted relay at `wss://raccoon.harbouli.dev/signal`). Put a TLS-terminating reverse proxy in front of this HTTP service and forward WebSocket upgrades at `/signal`; allow long-lived connections and frames up to 132 KiB. Use a persistent writable volume for the account file. Both phones need internet access to this domain. Direct TCP is attempted first; if it cannot connect, the server relays end-to-end encrypted fprot frames.

This is a small demonstration server, not a complete public identity service: account registration proves device-key ownership only; pair secrets are in memory and lost on restart; requests need production rate limiting, abuse controls, and durable pair storage before wide deployment. The relay adds bandwidth and availability costs to this server. No server-wide shared token is configured or embedded in the app.

## Test

```sh
npm test
```
