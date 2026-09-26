import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { WebSocket } from 'ws';
import { createRaccoonServer } from './index.mjs';

function identity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicId: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url'), privateKey };
}

function proof(owner, action) {
  const timestamp = Date.now();
  return { publicId: owner.publicId, timestamp,
    signature: sign(null, Buffer.from(action(timestamp, owner.publicId)), owner.privateKey).toString('base64url') };
}

async function post(url, body) {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

async function del(url, body) {
  const response = await fetch(url, { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'raccoon-server-'));
  const dataFile = join(directory, 'accounts.json');
  const instance = await createRaccoonServer({ port: 0, dataFile });
  t.after(() => instance.close());
  return { base: `http://127.0.0.1:${instance.server.address().port}`, dataFile, instance };
}

async function register(base, owner) {
  return post(`${base}/v1/accounts`, proof(owner, (time, id) => `fprot.account.v1:${time}:${id}`));
}

test('registers a device using only its identity proof and resolves its short ID', async t => {
  const { base, dataFile } = await fixture(t);
  const owner = identity();
  const registration = await register(base, owner);
  assert.equal(registration.status, 200);
  assert.match(registration.body.accountId, /^[A-Z2-9]{10}$/);
  const lookup = await fetch(`${base}/v1/accounts/${registration.body.accountId}`);
  assert.deepEqual(await lookup.json(), registration.body);
  assert.equal(JSON.parse(await readFile(dataFile, 'utf8'))[registration.body.accountId], owner.publicId);
});

test('rejects registration without a valid signature', async t => {
  const { base } = await fixture(t);
  const owner = identity();
  const result = await post(`${base}/v1/accounts`, { publicId: owner.publicId, timestamp: Date.now(), signature: 'invalid' });
  assert.equal(result.status, 400);
});

test('issues the same random pair token only to both participants and routes their signaling', async t => {
  const { base } = await fixture(t);
  const alice = identity(), bob = identity(), outsider = identity();
  const aliceId = (await register(base, alice)).body.accountId;
  const bobId = (await register(base, bob)).body.accountId;
  await register(base, outsider);
  const request = await post(`${base}/v1/pairs`, {
    ...proof(alice, (time, id) => `raccoon.pair.v1:${time}:${id}:${bobId}`), recipientAccountId: bobId,
  });
  assert.equal(request.status, 200);
  assert.match(request.body.token, /^[a-f0-9]{64}$/);
  assert.equal(request.body.accountId, bobId);

  const inbox = await post(`${base}/v1/invitations`, proof(bob, (time, id) => `raccoon.inbox.v1:${time}:${id}`));
  assert.deepEqual(inbox.body.invitations, [{ pairId: request.body.pairId, accountId: aliceId, publicId: alice.publicId }]);
  const accepted = await post(`${base}/v1/pairs/${request.body.pairId}/accept`,
    proof(bob, (time, id) => `raccoon.accept.v1:${time}:${id}:${request.body.pairId}`));
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.token, request.body.token);
  const unauthorizedAccept = await post(`${base}/v1/pairs/${request.body.pairId}/accept`,
    proof(outsider, (time, id) => `raccoon.accept.v1:${time}:${id}:${request.body.pairId}`));
  assert.equal(unauthorizedAccept.status, 404);

  async function connect(owner) {
    const socket = new WebSocket(base.replace(/^http/, 'ws') + '/signal');
    const challenge = await new Promise(resolve => socket.once('message', bytes => resolve(JSON.parse(bytes))));
    socket.send(JSON.stringify({ type: 'auth', token: request.body.token, publicKey: owner.publicId,
      signature: sign(null, Buffer.from(`fprot.broker.v1:${challenge.nonce}`), owner.privateKey).toString('base64url') }));
    const reply = await new Promise(resolve => socket.once('message', bytes => resolve(JSON.parse(bytes))));
    assert.equal(reply.type, 'ready');
    t.after(() => socket.terminate());
    return socket;
  }
  const aliceSocket = await connect(alice), bobSocket = await connect(bob);
  const envelope = JSON.stringify({ body: JSON.stringify({ from: alice.publicId, to: bob.publicId }), signature: 'opaque' });
  const delivered = new Promise(resolve => bobSocket.once('message', bytes => resolve(JSON.parse(bytes))));
  aliceSocket.send(JSON.stringify({ type: 'signal', data: envelope }));
  assert.deepEqual(await delivered, { type: 'signal', data: envelope });

  const encryptedFrame = JSON.stringify({ sessionId: '0123456789abcdef', frame: {
    v: 1, nonce: 'opaque-nonce', ciphertext: 'opaque-ciphertext',
  } });
  const relayed = new Promise(resolve => bobSocket.once('message', bytes => resolve(JSON.parse(bytes))));
  aliceSocket.send(JSON.stringify({ type: 'relay', data: encryptedFrame }));
  assert.deepEqual(await relayed, { type: 'relay', data: encryptedFrame });

  const rejected = new Promise(resolve => aliceSocket.once('close', code => resolve(code)));
  aliceSocket.send(JSON.stringify({ type: 'relay', data: 'x'.repeat(64 * 1024 + 1) }));
  assert.equal(await rejected, 1008);
});

test('entering each other’s IDs accepts the existing pair without a second token', async t => {
  const { base } = await fixture(t);
  const alice = identity(), bob = identity();
  const aliceId = (await register(base, alice)).body.accountId;
  const bobId = (await register(base, bob)).body.accountId;
  const first = await post(`${base}/v1/pairs`, {
    ...proof(alice, (time, id) => `raccoon.pair.v1:${time}:${id}:${bobId}`), recipientAccountId: bobId,
  });
  const second = await post(`${base}/v1/pairs`, {
    ...proof(bob, (time, id) => `raccoon.pair.v1:${time}:${id}:${aliceId}`), recipientAccountId: aliceId,
  });
  assert.equal(second.status, 200);
  assert.equal(second.body.token, first.body.token);
  const inbox = await post(`${base}/v1/invitations`, proof(bob, (time, id) => `raccoon.inbox.v1:${time}:${id}`));
  assert.deepEqual(inbox.body.invitations, []);
});

test('registers and removes device push tokens with signature proofs', async t => {
  const { base, instance } = await fixture(t);
  const alice = identity();
  await register(base, alice);

  const tokenData = 'apns-test-device-token-123';
  const regResult = await post(`${base}/v1/tokens`, {
    ...proof(alice, (time, id) => `raccoon.token.v1:${time}:${id}:ios:${tokenData}`),
    platform: 'ios',
    token: tokenData,
  });
  assert.equal(regResult.status, 200);
  assert.equal(regResult.body.ok, true);
  assert.equal(regResult.body.token, tokenData);

  const tokensInDb = instance.db.getDeviceTokens(alice.publicId);
  assert.equal(tokensInDb.length, 1);
  assert.equal(tokensInDb[0].platform, 'ios');
  assert.equal(tokensInDb[0].token, tokenData);

  // Deleting token
  const delResult = await del(`${base}/v1/tokens`, {
    ...proof(alice, (time, id) => `raccoon.untoken.v1:${time}:${id}:ios`),
    platform: 'ios',
  });
  assert.equal(delResult.status, 200);
  assert.equal(delResult.body.ok, true);

  const tokensAfterDel = instance.db.getDeviceTokens(alice.publicId);
  assert.equal(tokensAfterDel.length, 0);
});

test('queues offline relay messages in SQLite mailbox and triggers push dispatch, then delivers upon reconnect', async t => {
  const { base, instance } = await fixture(t);
  const alice = identity(), bob = identity();
  const aliceId = (await register(base, alice)).body.accountId;
  const bobId = (await register(base, bob)).body.accountId;

  // Register Bob's push token
  const bobPushToken = 'bob-apns-push-token-xyz';
  await post(`${base}/v1/tokens`, {
    ...proof(bob, (time, id) => `raccoon.token.v1:${time}:${id}:ios:${bobPushToken}`),
    platform: 'ios',
    token: bobPushToken,
  });

  // Pair Alice & Bob
  const pairReq = await post(`${base}/v1/pairs`, {
    ...proof(alice, (time, id) => `raccoon.pair.v1:${time}:${id}:${bobId}`),
    recipientAccountId: bobId,
  });
  await post(`${base}/v1/pairs/${pairReq.body.pairId}/accept`,
    proof(bob, (time, id) => `raccoon.accept.v1:${time}:${id}:${pairReq.body.pairId}`));

  async function connect(owner) {
    const socket = new WebSocket(base.replace(/^http/, 'ws') + '/signal');
    const challenge = await new Promise(resolve => socket.once('message', bytes => resolve(JSON.parse(bytes))));
    socket.send(JSON.stringify({
      type: 'auth',
      token: pairReq.body.token,
      publicKey: owner.publicId,
      signature: sign(null, Buffer.from(`fprot.broker.v1:${challenge.nonce}`), owner.privateKey).toString('base64url'),
    }));
    const reply = await new Promise(resolve => socket.once('message', bytes => resolve(JSON.parse(bytes))));
    assert.equal(reply.type, 'ready');
    t.after(() => socket.terminate());
    return socket;
  }

  // Connect only Alice (Bob is offline)
  const aliceSocket = await connect(alice);

  const encryptedOfflineMessage = JSON.stringify({
    sessionId: 'session-offline',
    frame: { v: 1, nonce: 'offline-nonce', ciphertext: 'offline-secret-text' },
  });

  // Alice sends a relay frame while Bob is offline
  const relayAckPromise = new Promise(resolve => aliceSocket.once('message', bytes => resolve(JSON.parse(bytes))));
  aliceSocket.send(JSON.stringify({
    type: 'relay',
    id: 'msg-offline-101',
    data: encryptedOfflineMessage,
  }));

  const relayAck = await relayAckPromise;
  assert.equal(relayAck.type, 'relay_ack');
  assert.equal(relayAck.status, 'stored_offline');
  assert.equal(relayAck.id, 'msg-offline-101');

  // Verify message is in SQLite mailbox
  const queuedInDb = instance.db.getMailboxMessages(bob.publicId);
  assert.equal(queuedInDb.length, 1);
  assert.equal(queuedInDb[0].id, 'msg-offline-101');
  assert.equal(queuedInDb[0].payload, encryptedOfflineMessage);

  // Verify push dispatch was recorded
  const dispatches = instance.push.getDispatches();
  assert.equal(dispatches.length, 1);
  assert.equal(dispatches[0].token, bobPushToken);
  assert.equal(dispatches[0].title, 'New Message');

  // Now Bob comes online and connects
  const bobSocket = new WebSocket(base.replace(/^http/, 'ws') + '/signal');
  const challenge = await new Promise(resolve => bobSocket.once('message', bytes => resolve(JSON.parse(bytes))));
  bobSocket.send(JSON.stringify({
    type: 'auth',
    token: pairReq.body.token,
    publicKey: bob.publicId,
    signature: sign(null, Buffer.from(`fprot.broker.v1:${challenge.nonce}`), bob.privateKey).toString('base64url'),
  }));

  // Bob should receive 'ready' and 'mailbox_deliver'
  const receivedMessages = [];
  await new Promise(resolve => {
    bobSocket.on('message', bytes => {
      const msg = JSON.parse(bytes);
      receivedMessages.push(msg);
      if (receivedMessages.length === 2) resolve();
    });
  });
  t.after(() => bobSocket.terminate());

  const readyMsg = receivedMessages.find(m => m.type === 'ready');
  const mailboxMsg = receivedMessages.find(m => m.type === 'mailbox_deliver');
  assert.ok(readyMsg, 'Bob should receive ready');
  assert.ok(mailboxMsg, 'Bob should receive mailbox_deliver');
  assert.equal(mailboxMsg.messages.length, 1);
  assert.equal(mailboxMsg.messages[0].id, 'msg-offline-101');
  assert.equal(mailboxMsg.messages[0].payload, encryptedOfflineMessage);

  // Bob sends mailbox_ack
  bobSocket.send(JSON.stringify({ type: 'mailbox_ack', ids: ['msg-offline-101'] }));

  // Wait brief moment for DB delete
  await new Promise(r => setTimeout(r, 50));
  const mailboxAfterAck = instance.db.getMailboxMessages(bob.publicId);
  assert.equal(mailboxAfterAck.length, 0, 'Mailbox should be empty after ACK');
});
