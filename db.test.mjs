import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDatabase } from './db.mjs';

test('accounts: create, get by id, get by publicId', () => {
  const db = createDatabase(':memory:');
  const account = db.createAccount('ABCDEFGHIJ', 'public-key-1');
  assert.equal(account.accountId, 'ABCDEFGHIJ');
  assert.equal(account.publicId, 'public-key-1');

  const byId = db.getAccount('ABCDEFGHIJ');
  assert.deepEqual(byId, account);

  const byPub = db.getAccountByPublicId('public-key-1');
  assert.deepEqual(byPub, account);

  const nonExistent = db.getAccount('NONEXIST12');
  assert.equal(nonExistent, undefined);
  db.close();
});

test('pairs: create, query, accept, list invitations', () => {
  const db = createDatabase(':memory:');
  const pair = db.createPair({
    id: 'pair-123',
    token: 'token-456',
    initiator: 'pub-alice',
    recipient: 'pub-bob',
    accepted: false,
  });
  assert.equal(pair.accepted, false);

  const retrieved = db.getPair('pair-123');
  assert.equal(retrieved?.id, 'pair-123');
  assert.equal(retrieved?.accepted, false);

  const between = db.getPairBetween('pub-bob', 'pub-alice');
  assert.equal(between?.id, 'pair-123');

  const invitations = db.getInvitations('pub-bob');
  assert.equal(invitations.length, 1);
  assert.equal(invitations[0].pairId, 'pair-123');

  db.acceptPair('pair-123');
  const accepted = db.getPair('pair-123');
  assert.equal(accepted?.accepted, true);

  const pendingAfterAccept = db.getInvitations('pub-bob');
  assert.equal(pendingAfterAccept.length, 0);
  db.close();
});

test('device tokens: upsert, query, delete', () => {
  const db = createDatabase(':memory:');
  db.upsertDeviceToken('pub-alice', 'ios', 'apns-token-123');
  let tokens = db.getDeviceTokens('pub-alice');
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].platform, 'ios');
  assert.equal(tokens[0].token, 'apns-token-123');

  // Updating same platform overwrites token
  db.upsertDeviceToken('pub-alice', 'ios', 'apns-token-new');
  tokens = db.getDeviceTokens('pub-alice');
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].token, 'apns-token-new');

  // Add android token
  db.upsertDeviceToken('pub-alice', 'android', 'fcm-token-456');
  tokens = db.getDeviceTokens('pub-alice');
  assert.equal(tokens.length, 2);

  // Remove iOS token
  db.removeDeviceToken('pub-alice', 'ios');
  tokens = db.getDeviceTokens('pub-alice');
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].platform, 'android');
  db.close();
});

test('mailbox: store, retrieve, delete on ACK, and prune', () => {
  const db = createDatabase(':memory:');
  const now = Date.now();
  db.storeMailboxMessage({
    id: 'msg-1',
    pairId: 'pair-123',
    recipientPublicId: 'pub-bob',
    senderPublicId: 'pub-alice',
    payload: 'opaque-payload-1',
    createdAt: now - 1000,
  });
  db.storeMailboxMessage({
    id: 'msg-2',
    pairId: 'pair-123',
    recipientPublicId: 'pub-bob',
    senderPublicId: 'pub-alice',
    payload: 'opaque-payload-2',
    createdAt: now,
  });

  let bobMessages = db.getMailboxMessages('pub-bob');
  assert.equal(bobMessages.length, 2);
  assert.equal(bobMessages[0].id, 'msg-1');
  assert.equal(bobMessages[1].id, 'msg-2');

  // Delete single message by id
  db.deleteMailboxMessages(['msg-1']);
  bobMessages = db.getMailboxMessages('pub-bob');
  assert.equal(bobMessages.length, 1);
  assert.equal(bobMessages[0].id, 'msg-2');

  // Add an expired message (15 days old)
  db.storeMailboxMessage({
    id: 'msg-old',
    pairId: 'pair-123',
    recipientPublicId: 'pub-bob',
    senderPublicId: 'pub-alice',
    payload: 'old-payload',
    createdAt: now - (15 * 24 * 60 * 60 * 1000),
  });
  assert.equal(db.getMailboxMessages('pub-bob').length, 2);

  // Prune (maxAge = 14 days)
  db.pruneExpiredMailbox(14 * 24 * 60 * 60 * 1000);
  bobMessages = db.getMailboxMessages('pub-bob');
  assert.equal(bobMessages.length, 1);
  assert.equal(bobMessages[0].id, 'msg-2');

  db.close();
});
