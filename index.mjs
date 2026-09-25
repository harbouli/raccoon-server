#!/usr/bin/env node

import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import express from 'express';
import { WebSocket, WebSocketServer } from 'ws';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_SIGNAL_BYTES = 128 * 1024;

function publicKeyFor(publicId) {
  if (typeof publicId !== 'string') throw new Error('Invalid public ID');
  const raw = Buffer.from(publicId, 'base64url');
  if (raw.length !== 32 || raw.toString('base64url') !== publicId) throw new Error('Invalid public ID');
  return createPublicKey({ key: Buffer.concat([PUBLIC_KEY_PREFIX, raw]), format: 'der', type: 'spki' });
}

function accountIdFor(publicId) {
  const bytes = createHash('sha256').update(publicId).digest();
  let bits = 0, value = 0, accountId = '';
  for (const byte of bytes) {
    value = value * 256 + byte;
    bits += 8;
    while (bits >= 5 && accountId.length < 10) {
      bits -= 5;
      accountId += ALPHABET[Math.floor(value / 2 ** bits) % 32];
      value %= 2 ** bits;
    }
    if (accountId.length === 10) return accountId;
  }
  throw new Error('Could not create account ID');
}

function normalizedId(value) {
  const id = String(value).replaceAll('-', '').toUpperCase();
  if (!new RegExp(`^[${ALPHABET}]{10}$`).test(id)) throw new Error('Enter a valid 10-character account ID');
  return id;
}

function verifyProof({ publicId, timestamp, signature }, action) {
  const time = Number(timestamp);
  if (!Number.isSafeInteger(time) || Math.abs(Date.now() - time) > 5 * 60_000) throw new Error('Signed request is expired');
  const key = publicKeyFor(publicId);
  if (typeof signature !== 'string' || !verify(null, Buffer.from(action(time, publicId)), key, Buffer.from(signature, 'base64url'))) {
    throw new Error('Invalid identity ownership proof');
  }
}

async function loadAccounts(dataFile) {
  try { return new Map(Object.entries(JSON.parse(await readFile(dataFile, 'utf8')))); }
  catch (error) { if (error?.code === 'ENOENT') return new Map(); throw error; }
}

async function saveAccounts(dataFile, accounts) {
  await mkdir(dirname(dataFile), { recursive: true });
  const temporary = `${dataFile}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(Object.fromEntries(accounts), null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, dataFile);
}

function sameSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function createRaccoonServer({
  host = '127.0.0.1',
  port = 8787,
  dataFile = resolve(dirname(fileURLToPath(import.meta.url)), 'data', 'accounts.json'),
} = {}) {
  const accounts = await loadAccounts(dataFile);
  // Pair secrets are ephemeral. A server restart requires users to request pairing again.
  const pairs = new Map(), peers = new Map();
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '8kb' }));

  function requireRegistered(publicId) {
    if (accounts.get(accountIdFor(publicId)) !== publicId) throw new Error('Register this device first');
  }

  app.get('/health', (_request, response) => response.json({ ok: true, connectedPeers: peers.size }));

  app.post('/v1/accounts', async (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    verifyProof({ publicId, timestamp, signature }, (time, id) => `fprot.account.v1:${time}:${id}`);
    const accountId = accountIdFor(publicId), existing = accounts.get(accountId);
    if (existing && existing !== publicId) return response.status(409).json({ error: 'Short account ID collision' });
    if (!existing) { accounts.set(accountId, publicId); await saveAccounts(dataFile, accounts); }
    response.json({ accountId, publicId });
  });

  app.get('/v1/accounts/:accountId', (request, response) => {
    const accountId = normalizedId(request.params.accountId), publicId = accounts.get(accountId);
    if (!publicId) return response.status(404).json({ error: 'Account ID was not found' });
    response.json({ accountId, publicId });
  });

  app.post('/v1/pairs', (request, response) => {
    const { publicId, recipientAccountId, timestamp, signature } = request.body ?? {};
    const recipientId = normalizedId(recipientAccountId);
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.pair.v1:${time}:${id}:${recipientId}`);
    requireRegistered(publicId);
    const recipientPublicId = accounts.get(recipientId);
    if (!recipientPublicId) return response.status(404).json({ error: 'Friend ID was not found' });
    if (recipientPublicId === publicId) throw new Error('Enter another person’s ID');
    const key = [publicId, recipientPublicId].sort().join(':');
    let pair = pairs.get(key);
    if (!pair) {
      pair = { id: randomBytes(16).toString('hex'), token: randomBytes(32).toString('hex'),
        initiator: publicId, recipient: recipientPublicId, accepted: false };
      pairs.set(key, pair);
    } else if (pair.recipient === publicId) {
      // Entering each other's ID is also an explicit acceptance.
      pair.accepted = true;
    }
    response.json({ pairId: pair.id, token: pair.token, accountId: recipientId, publicId: recipientPublicId });
  });

  app.post('/v1/invitations', (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.inbox.v1:${time}:${id}`);
    requireRegistered(publicId);
    response.json({ invitations: [...pairs.values()].filter(pair => pair.recipient === publicId && !pair.accepted)
      .map(pair => ({ pairId: pair.id, accountId: accountIdFor(pair.initiator), publicId: pair.initiator })) });
  });

  app.post('/v1/pairs/:pairId/accept', (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    const pairId = request.params.pairId;
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.accept.v1:${time}:${id}:${pairId}`);
    requireRegistered(publicId);
    const pair = [...pairs.values()].find(candidate => candidate.id === pairId);
    if (!pair || pair.recipient !== publicId) return response.status(404).json({ error: 'Invitation was not found' });
    pair.accepted = true;
    response.json({ pairId, token: pair.token, accountId: accountIdFor(pair.initiator), publicId: pair.initiator });
  });

  app.use((error, _request, response, _next) => {
    response.status(error.status === 413 ? 413 : 400).json({ error: error instanceof Error ? error.message : 'Invalid request' });
  });

  const server = createServer(app);
  const sockets = new WebSocketServer({ server, path: '/signal', maxPayload: MAX_SIGNAL_BYTES + 4096, perMessageDeflate: false });
  sockets.on('connection', socket => {
    const nonce = randomBytes(32).toString('hex');
    let publicId, pair, alive = true, count = 0, windowStart = Date.now();
    const authTimeout = setTimeout(() => socket.close(1008, 'Authentication timeout'), 10_000);
    const pulse = setInterval(() => { if (!alive) return socket.terminate(); alive = false; socket.ping(); }, 30_000);
    socket.on('pong', () => { alive = true; });
    socket.on('error', () => socket.terminate());
    socket.send(JSON.stringify({ type: 'challenge', nonce }));
    socket.on('message', (bytes, binary) => {
      try {
        if (binary) throw new Error('Text messages only');
        if (Date.now() - windowStart > 60_000) { count = 0; windowStart = Date.now(); }
        if (++count > 120) throw new Error('Rate limit exceeded');
        const message = JSON.parse(bytes.toString());
        if (!publicId) {
          if (message.type !== 'auth' || typeof message.publicKey !== 'string' || typeof message.signature !== 'string') throw new Error('Authentication required');
          pair = [...pairs.values()].find(item => sameSecret(message.token, item.token));
          if (!pair) throw new Error('Unknown pair token');
          if (message.publicKey !== pair.initiator && (message.publicKey !== pair.recipient || !pair.accepted)) throw new Error('Device is not a participant in this pair');
          requireRegistered(message.publicKey);
          if (!verify(null, Buffer.from(`fprot.broker.v1:${nonce}`), publicKeyFor(message.publicKey), Buffer.from(message.signature, 'base64url'))) throw new Error('Invalid identity proof');
          publicId = message.publicKey;
          const key = `${pair.id}:${publicId}`;
          peers.get(key)?.close(1000, 'Identity reconnected');
          peers.set(key, socket);
          clearTimeout(authTimeout);
          socket.send(JSON.stringify({ type: 'ready' }));
          return;
        }
        if (message.type !== 'signal' || typeof message.data !== 'string' || message.data.length > MAX_SIGNAL_BYTES) throw new Error('Invalid signal');
        const body = JSON.parse(JSON.parse(message.data).body);
        const other = publicId === pair.initiator ? pair.recipient : pair.initiator;
        if (body.from !== publicId || body.to !== other) throw new Error('Invalid signal route');
        const destination = peers.get(`${pair.id}:${other}`);
        if (destination?.readyState === WebSocket.OPEN) destination.send(JSON.stringify({ type: 'signal', data: message.data }));
      } catch { socket.close(1008, 'Invalid or unauthorized request'); }
    });
    socket.on('close', () => {
      clearTimeout(authTimeout); clearInterval(pulse);
      if (publicId && pair && peers.get(`${pair.id}:${publicId}`) === socket) peers.delete(`${pair.id}:${publicId}`);
    });
  });

  await new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolvePromise(); });
  });
  return { app, server, sockets, async close() {
    for (const socket of sockets.clients) socket.terminate();
    await new Promise(resolvePromise => sockets.close(resolvePromise));
    await new Promise((resolvePromise, reject) => server.close(error => error ? reject(error) : resolvePromise()));
  } };
}

const entryPoint = process.env.pm_exec_path ?? process.argv[1];
if (entryPoint && import.meta.url === pathToFileURL(entryPoint).href) {
  const instance = await createRaccoonServer({ host: process.env.RACCOON_HOST ?? '0.0.0.0',
    port: Number(process.env.RACCOON_PORT ?? 8787), dataFile: process.env.RACCOON_ACCOUNT_FILE });
  process.stdout.write(`Raccoon server listening on ${JSON.stringify(instance.server.address())}\n`);
  const shutdown = async () => { await instance.close(); process.exit(0); };
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
}
