# Raccoon signaling server

Standalone Node.js/Express server for the sibling RaccoonChat mobile app. It handles short-ID registration, signed connection requests, automatic 32-byte pair-token issuance, and fprot WebSocket signaling. It does **not** relay chat messages.

## Run locally

```sh
npm install
npm start
```

`GET /health` is available on port 8787. Optional environment variables: `RACCOON_HOST` (default `0.0.0.0` when started via npm), `RACCOON_PORT` (default `8787`), and `RACCOON_ACCOUNT_FILE` (default `data/accounts.json`). The accounts file is private to this server and ignored by Git.

## Deployment

Point the app's `src/config.ts` at `https://your-domain`. Put a TLS-terminating reverse proxy in front of this HTTP service and forward WebSocket upgrades at `/signal`. Use a persistent writable volume for the account file. The server must be reachable by both phones, but direct fprot TCP chat additionally needs the devices on the same LAN or a separately routed path.

This is a small demonstration server, not a complete public identity service: account registration proves device-key ownership only; pair secrets are in memory and lost on restart; requests need production rate limiting, abuse controls, and durable pair storage before wide deployment. No server-wide shared token is configured or embedded in the app.

## Test

```sh
npm test
```
