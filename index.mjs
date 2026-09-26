#!/usr/bin/env node

import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import express from 'express';
import { WebSocket, WebSocketServer } from 'ws';
import { createDatabase } from './db.mjs';
import { createPushService } from './push.mjs';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_RELAY_BYTES = 64 * 1024;
const MAX_BUFFERED_BYTES = 512 * 1024;
const MAX_MINUTE_BYTES = 4 * 1024 * 1024;

export function publicKeyFor(publicId) {
  if (typeof publicId !== 'string') throw new Error('Invalid public ID');
  const raw = Buffer.from(publicId, 'base64url');
  if (raw.length !== 32 || raw.toString('base64url') !== publicId) throw new Error('Invalid public ID');
  return createPublicKey({ key: Buffer.concat([PUBLIC_KEY_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function accountIdFor(publicId) {
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

export function normalizedId(value) {
  const id = String(value).replaceAll('-', '').toUpperCase();
  if (!new RegExp(`^[${ALPHABET}]{10}$`).test(id)) throw new Error('Enter a valid 10-character account ID');
  return id;
}

export function verifyProof({ publicId, timestamp, signature }, action) {
  const time = Number(timestamp);
  if (!Number.isSafeInteger(time) || Math.abs(Date.now() - time) > 5 * 60_000) throw new Error('Signed request is expired');
  const key = publicKeyFor(publicId);
  if (typeof signature !== 'string' || !verify(null, Buffer.from(action(time, publicId)), key, Buffer.from(signature, 'base64url'))) {
    throw new Error('Invalid identity ownership proof');
  }
}

async function syncJsonAccounts(dataFile, db) {
  if (!dataFile || !dataFile.endsWith('.json')) return;
  try {
    const all = db.getAllAccounts();
    const map = {};
    for (const acc of all) {
      map[acc.accountId] = acc.publicId;
    }
    await mkdir(dirname(dataFile), { recursive: true });
    const temporary = `${dataFile}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(map, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, dataFile);
  } catch (error) {
    console.warn('[server] Warning writing legacy json accounts:', error);
  }
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
  dbLocation,
  isDev = process.env.NODE_ENV !== 'production',
} = {}) {
  const sqlitePath = dbLocation ?? (
    dataFile === ':memory:'
      ? ':memory:'
      : (dataFile.endsWith('.json') ? dataFile.replace(/\.json$/, '.db') : resolve(dirname(fileURLToPath(import.meta.url)), 'data', 'raccoon.db'))
  );
  const db = createDatabase(sqlitePath);
  if (dataFile && dataFile.endsWith('.json')) {
    await db.migrateFromJson(dataFile);
    await syncJsonAccounts(dataFile, db);
  }

  const push = createPushService({ db, isDev });
  const peers = new Map();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '8kb' }));

  function requireRegistered(publicId) {
    const acc = db.getAccount(accountIdFor(publicId));
    if (!acc || acc.publicId !== publicId) throw new Error('Register this device first');
  }

  app.get('/health', (_request, response) => response.json({ ok: true, connectedPeers: peers.size }));

  app.post('/v1/accounts', async (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    verifyProof({ publicId, timestamp, signature }, (time, id) => `fprot.account.v1:${time}:${id}`);
    const accountId = accountIdFor(publicId);
    const existing = db.getAccount(accountId);
    if (existing && existing.publicId !== publicId) return response.status(409).json({ error: 'Short account ID collision' });
    if (!existing) {
      db.createAccount(accountId, publicId);
      await syncJsonAccounts(dataFile, db);
    }
    response.json({ accountId, publicId });
  });

  app.get('/v1/accounts/:accountId', (request, response) => {
    const accountId = normalizedId(request.params.accountId);
    const acc = db.getAccount(accountId);
    if (!acc) return response.status(404).json({ error: 'Account ID was not found' });
    response.json({ accountId: acc.accountId, publicId: acc.publicId });
  });

  app.post('/v1/pairs', (request, response) => {
    const { publicId, recipientAccountId, timestamp, signature } = request.body ?? {};
    const recipientId = normalizedId(recipientAccountId);
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.pair.v1:${time}:${id}:${recipientId}`);
    requireRegistered(publicId);
    const recipientAcc = db.getAccount(recipientId);
    if (!recipientAcc) return response.status(404).json({ error: 'Friend ID was not found' });
    const recipientPublicId = recipientAcc.publicId;
    if (recipientPublicId === publicId) throw new Error('Enter another person’s ID');

    let pair = db.getPairBetween(publicId, recipientPublicId);
    if (!pair) {
      pair = db.createPair({
        id: randomBytes(16).toString('hex'),
        token: randomBytes(32).toString('hex'),
        initiator: publicId,
        recipient: recipientPublicId,
        accepted: false,
      });
    } else if (pair.recipient === publicId) {
      // Entering each other's ID is also an explicit acceptance.
      db.acceptPair(pair.id);
      pair = db.getPair(pair.id);
    }
    response.json({ pairId: pair.id, token: pair.token, accountId: recipientId, publicId: recipientPublicId });
  });

  app.post('/v1/invitations', (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.inbox.v1:${time}:${id}`);
    requireRegistered(publicId);
    const invitations = db.getInvitations(publicId).map(pair => ({
      pairId: pair.pairId,
      accountId: accountIdFor(pair.initiator),
      publicId: pair.initiator,
    }));
    response.json({ invitations });
  });

  app.post('/v1/pairs/:pairId/accept', (request, response) => {
    const { publicId, timestamp, signature } = request.body ?? {};
    const pairId = request.params.pairId;
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.accept.v1:${time}:${id}:${pairId}`);
    requireRegistered(publicId);
    const pair = db.getPair(pairId);
    if (!pair || pair.recipient !== publicId) return response.status(404).json({ error: 'Invitation was not found' });
    db.acceptPair(pair.id);
    response.json({ pairId, token: pair.token, accountId: accountIdFor(pair.initiator), publicId: pair.initiator });
  });

  // Device push tokens endpoints
  app.post('/v1/tokens', (request, response) => {
    const { publicId, platform, token, timestamp, signature } = request.body ?? {};
    if (!['ios', 'android', 'web'].includes(platform)) {
      return response.status(400).json({ error: 'Invalid platform: must be ios, android, or web' });
    }
    if (typeof token !== 'string' || !token.trim()) {
      return response.status(400).json({ error: 'Device token cannot be empty' });
    }
    const cleanToken = token.trim();
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.token.v1:${time}:${id}:${platform}:${cleanToken}`);
    requireRegistered(publicId);
    db.upsertDeviceToken(publicId, platform, cleanToken);
    response.json({ ok: true, publicId, platform, token: cleanToken });
  });

  app.delete('/v1/tokens', (request, response) => {
    const { publicId, platform, timestamp, signature } = request.body ?? {};
    if (!['ios', 'android', 'web'].includes(platform)) {
      return response.status(400).json({ error: 'Invalid platform' });
    }
    verifyProof({ publicId, timestamp, signature }, (time, id) => `raccoon.untoken.v1:${time}:${id}:${platform}`);
    requireRegistered(publicId);
    db.removeDeviceToken(publicId, platform);
    response.json({ ok: true });
  });

  app.use((error, _request, response, _next) => {
    response.status(error.status === 413 ? 413 : 400).json({ error: error instanceof Error ? error.message : 'Invalid request' });
  });

  const server = createServer(app);
  const sockets = new WebSocketServer({ server, path: '/signal', maxPayload: MAX_SIGNAL_BYTES + 4096, perMessageDeflate: false });

  // Periodically prune old offline messages from mailbox (every 1 hour)
  const pruneTimer = setInterval(() => {
    try {
      db.pruneExpiredMailbox();
    } catch (e) {
      console.warn('[server] Error pruning expired mailbox messages:', e);
    }
  }, 3600_000);

  sockets.on('connection', socket => {
    const nonce = randomBytes(32).toString('hex');
    let publicId, pair, alive = true, count = 0, minuteBytes = 0, windowStart = Date.now();
    const authTimeout = setTimeout(() => socket.close(1008, 'Authentication timeout'), 10_000);
    const pulse = setInterval(() => { if (!alive) return socket.terminate(); alive = false; socket.ping(); }, 30_000);
    socket.on('pong', () => { alive = true; });
    socket.on('error', () => socket.terminate());
    socket.send(JSON.stringify({ type: 'challenge', nonce }));

    socket.on('message', (bytes, binary) => {
      try {
        if (binary) throw new Error('Text messages only');
        if (Date.now() - windowStart > 60_000) { count = 0; minuteBytes = 0; windowStart = Date.now(); }
        minuteBytes += bytes.length;
        if (++count > 120 || minuteBytes > MAX_MINUTE_BYTES) throw new Error('Rate limit exceeded');
        const message = JSON.parse(bytes.toString());

        if (!publicId) {
          if (message.type !== 'auth' || typeof message.publicKey !== 'string' || typeof message.signature !== 'string') {
            throw new Error('Authentication required');
          }
          pair = db.getPairByToken(message.token);
          if (!pair) throw new Error('Unknown pair token');
          if (message.publicKey !== pair.initiator && (message.publicKey !== pair.recipient || !pair.accepted)) {
            throw new Error('Device is not a participant in this pair');
          }
          requireRegistered(message.publicKey);
          if (!verify(null, Buffer.from(`fprot.broker.v1:${nonce}`), publicKeyFor(message.publicKey), Buffer.from(message.signature, 'base64url'))) {
            throw new Error('Invalid identity proof');
          }
          publicId = message.publicKey;
          const key = `${pair.id}:${publicId}`;
          peers.get(key)?.close(1000, 'Identity reconnected');
          peers.set(key, socket);
          clearTimeout(authTimeout);
          socket.send(JSON.stringify({ type: 'ready' }));

          // Stream pending offline mailbox messages
          const queued = db.getMailboxMessages(publicId);
          if (queued.length > 0) {
            socket.send(JSON.stringify({
              type: 'mailbox_deliver',
              messages: queued.map(m => ({
                id: m.id,
                pairId: m.pairId,
                sender: m.senderPublicId,
                payload: m.payload,
                createdAt: m.createdAt,
              })),
            }));
          }
          return;
        }

        // Handle mailbox acknowledgements
        if (message.type === 'mailbox_ack') {
          if (Array.isArray(message.ids) && message.ids.length > 0) {
            db.deleteMailboxMessages(message.ids);
          }
          return;
        }

        if (typeof message.data !== 'string') throw new Error('Invalid message');
        const other = publicId === pair.initiator ? pair.recipient : pair.initiator;

        if (message.type === 'signal') {
          if (message.data.length > MAX_SIGNAL_BYTES) throw new Error('Invalid signal');
          const body = JSON.parse(JSON.parse(message.data).body);
          if (body.from !== publicId || body.to !== other) throw new Error('Invalid signal route');
          const destination = peers.get(`${pair.id}:${other}`);
          if (destination?.readyState === WebSocket.OPEN) {
            if (destination.bufferedAmount > MAX_BUFFERED_BYTES) return socket.close(1013, 'Recipient is too slow');
            destination.send(JSON.stringify({ type: message.type, data: message.data }));
          } else {
            // Wakeup push notification to offline recipient
            void push.dispatchToPublicId(other, {
              title: 'Incoming Connection',
              body: 'A contact is attempting to connect with you.',
              data: { type: 'signal', pairId: pair.id, senderAccountId: accountIdFor(publicId) },
            });
          }
        } else if (message.type === 'relay') {
          // Opaque fprot-encrypted frames only. The server never receives session keys.
          if (!message.data.length || message.data.length > MAX_RELAY_BYTES) throw new Error('Invalid relay frame');
          const destination = peers.get(`${pair.id}:${other}`);
          if (destination?.readyState === WebSocket.OPEN) {
            if (destination.bufferedAmount > MAX_BUFFERED_BYTES) return socket.close(1013, 'Recipient is too slow');
            destination.send(JSON.stringify({ type: message.type, data: message.data }));
            if (message.id) {
              socket.send(JSON.stringify({ type: 'relay_ack', status: 'delivered', id: message.id }));
            }
          } else {
            // Recipient is offline/backgrounded: store encrypted frame in SQLite mailbox and alert
            const msgId = typeof message.id === 'string' && message.id.length > 0
              ? message.id
              : randomBytes(12).toString('hex');
            db.storeMailboxMessage({
              id: msgId,
              pairId: pair.id,
              recipientPublicId: other,
              senderPublicId: publicId,
              payload: message.data,
            });
            void push.dispatchToPublicId(other, {
              title: 'New Message',
              body: 'You received an encrypted message.',
              data: { type: 'message', pairId: pair.id, senderAccountId: accountIdFor(publicId), messageId: msgId },
            });
            socket.send(JSON.stringify({ type: 'relay_ack', status: 'stored_offline', id: msgId }));
          }
        } else throw new Error('Invalid message type');
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

  return {
    app,
    server,
    sockets,
    db,
    push,
    async close() {
      clearInterval(pruneTimer);
      for (const socket of sockets.clients) socket.terminate();
      await new Promise(resolvePromise => sockets.close(resolvePromise));
      await new Promise((resolvePromise, reject) => server.close(error => error ? reject(error) : resolvePromise()));
      db.close();
    },
  };
}

const entryPoint = process.env.pm_exec_path ?? process.argv[1];
if (entryPoint && import.meta.url === pathToFileURL(entryPoint).href) {
  const instance = await createRaccoonServer({
    host: process.env.RACCOON_HOST ?? '0.0.0.0',
    port: Number(process.env.RACCOON_PORT ?? 8787),
    dataFile: process.env.RACCOON_ACCOUNT_FILE,
  });
  process.stdout.write(`Raccoon server listening on ${JSON.stringify(instance.server.address())}\n`);
  const shutdown = async () => { await instance.close(); process.exit(0); };
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
}
