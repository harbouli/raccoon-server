import { DatabaseSync } from 'node:sqlite';
import { readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { mkdir } from 'node:fs/promises';

export function createDatabase(location = ':memory:') {
  if (location !== ':memory:') {
    mkdir(dirname(location), { recursive: true }).catch(() => {});
  }

  const db = new DatabaseSync(location);
  let closed = false;

  // Enable WAL mode for concurrency and durability if not in-memory
  if (location !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }

  // Schema creation
  db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      account_id TEXT PRIMARY KEY,
      public_id TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pairs (
      pair_id TEXT PRIMARY KEY,
      token TEXT NOT NULL UNIQUE,
      initiator TEXT NOT NULL,
      recipient TEXT NOT NULL,
      accepted INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS device_tokens (
      public_id TEXT NOT NULL,
      platform TEXT NOT NULL,
      token TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (public_id, platform)
    );

    CREATE INDEX IF NOT EXISTS idx_device_tokens_public_id ON device_tokens(public_id);

    CREATE TABLE IF NOT EXISTS mailbox (
      id TEXT PRIMARY KEY,
      pair_id TEXT NOT NULL,
      recipient_public_id TEXT NOT NULL,
      sender_public_id TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_public_id);
    CREATE INDEX IF NOT EXISTS idx_mailbox_created ON mailbox(created_at);
  `);

  // Prepared Statements
  const stmts = {
    getAccountById: db.prepare('SELECT account_id AS accountId, public_id AS publicId, created_at AS createdAt FROM accounts WHERE account_id = ?'),
    getAccountByPublicId: db.prepare('SELECT account_id AS accountId, public_id AS publicId, created_at AS createdAt FROM accounts WHERE public_id = ?'),
    insertAccount: db.prepare('INSERT INTO accounts (account_id, public_id, created_at) VALUES (?, ?, ?)'),
    getAllAccounts: db.prepare('SELECT account_id AS accountId, public_id AS publicId, created_at AS createdAt FROM accounts'),

    getPairById: db.prepare('SELECT pair_id AS id, token, initiator, recipient, accepted, created_at AS createdAt FROM pairs WHERE pair_id = ?'),
    getPairByToken: db.prepare('SELECT pair_id AS id, token, initiator, recipient, accepted, created_at AS createdAt FROM pairs WHERE token = ?'),
    getPairBetween: db.prepare(`
      SELECT pair_id AS id, token, initiator, recipient, accepted, created_at AS createdAt
      FROM pairs
      WHERE (initiator = ? AND recipient = ?) OR (initiator = ? AND recipient = ?)
    `),
    insertPair: db.prepare('INSERT INTO pairs (pair_id, token, initiator, recipient, accepted, created_at) VALUES (?, ?, ?, ?, ?, ?)'),
    acceptPair: db.prepare('UPDATE pairs SET accepted = 1 WHERE pair_id = ?'),
    getInvitations: db.prepare(`
      SELECT pair_id AS pairId, initiator, recipient
      FROM pairs
      WHERE recipient = ? AND accepted = 0
    `),
    getAllPairs: db.prepare('SELECT pair_id AS id, token, initiator, recipient, accepted, created_at AS createdAt FROM pairs'),

    upsertDeviceToken: db.prepare(`
      INSERT INTO device_tokens (public_id, platform, token, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(public_id, platform) DO UPDATE SET token = excluded.token, updated_at = excluded.updated_at
    `),
    removeDeviceToken: db.prepare('DELETE FROM device_tokens WHERE public_id = ? AND platform = ?'),
    getDeviceTokens: db.prepare('SELECT platform, token, updated_at AS updatedAt FROM device_tokens WHERE public_id = ?'),

    insertMailbox: db.prepare('INSERT INTO mailbox (id, pair_id, recipient_public_id, sender_public_id, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)'),
    getMailbox: db.prepare('SELECT id, pair_id AS pairId, recipient_public_id AS recipientPublicId, sender_public_id AS senderPublicId, payload, created_at AS createdAt FROM mailbox WHERE recipient_public_id = ? ORDER BY created_at ASC'),
    deleteMailboxSingle: db.prepare('DELETE FROM mailbox WHERE id = ?'),
    pruneMailbox: db.prepare('DELETE FROM mailbox WHERE created_at < ?'),
  };

  return {
    rawDb: db,

    async migrateFromJson(jsonPath) {
      try {
        const content = await readFile(jsonPath, 'utf8');
        const parsed = JSON.parse(content);
        const now = Date.now();
        for (const [accountId, publicId] of Object.entries(parsed)) {
          const existing = stmts.getAccountById.get(accountId);
          if (!existing) {
            stmts.insertAccount.run(accountId, publicId, now);
          }
        }
      } catch (error) {
        if (error?.code !== 'ENOENT') {
          console.warn('[db] Error migrating accounts.json:', error);
        }
      }
    },

    getAccount(accountId) {
      const row = stmts.getAccountById.get(accountId);
      return row ? { ...row } : undefined;
    },

    getAccountByPublicId(publicId) {
      const row = stmts.getAccountByPublicId.get(publicId);
      return row ? { ...row } : undefined;
    },

    createAccount(accountId, publicId, createdAt = Date.now()) {
      stmts.insertAccount.run(accountId, publicId, createdAt);
      return { accountId, publicId, createdAt };
    },

    getAllAccounts() {
      return stmts.getAllAccounts.all().map(r => ({ ...r }));
    },

    getPair(pairId) {
      const row = stmts.getPairById.get(pairId);
      if (!row) return undefined;
      return { ...row, accepted: Boolean(row.accepted) };
    },

    getPairByToken(token) {
      const row = stmts.getPairByToken.get(token);
      if (!row) return undefined;
      return { ...row, accepted: Boolean(row.accepted) };
    },

    getPairBetween(id1, id2) {
      const row = stmts.getPairBetween.get(id1, id2, id2, id1);
      if (!row) return undefined;
      return { ...row, accepted: Boolean(row.accepted) };
    },

    createPair({ id, token, initiator, recipient, accepted = false, createdAt = Date.now() }) {
      stmts.insertPair.run(id, token, initiator, recipient, accepted ? 1 : 0, createdAt);
      return { id, token, initiator, recipient, accepted, createdAt };
    },

    acceptPair(pairId) {
      stmts.acceptPair.run(pairId);
    },

    getInvitations(recipientPublicId) {
      return stmts.getInvitations.all(recipientPublicId).map(r => ({ ...r }));
    },

    getAllPairs() {
      return stmts.getAllPairs.all().map(p => ({ ...p, accepted: Boolean(p.accepted) }));
    },

    upsertDeviceToken(publicId, platform, token, updatedAt = Date.now()) {
      stmts.upsertDeviceToken.run(publicId, platform, token, updatedAt);
      return { publicId, platform, token, updatedAt };
    },

    removeDeviceToken(publicId, platform) {
      if (closed) return;
      try {
        stmts.removeDeviceToken.run(publicId, platform);
      } catch {}
    },

    getDeviceTokens(publicId) {
      if (closed) return [];
      try {
        return stmts.getDeviceTokens.all(publicId).map(r => ({ ...r }));
      } catch {
        return [];
      }
    },

    storeMailboxMessage({ id, pairId, recipientPublicId, senderPublicId, payload, createdAt = Date.now() }) {
      stmts.insertMailbox.run(id, pairId, recipientPublicId, senderPublicId, payload, createdAt);
      return { id, pairId, recipientPublicId, senderPublicId, payload, createdAt };
    },

    getMailboxMessages(recipientPublicId) {
      return stmts.getMailbox.all(recipientPublicId).map(r => ({ ...r }));
    },

    deleteMailboxMessages(ids) {
      if (!Array.isArray(ids) || ids.length === 0) return 0;
      let count = 0;
      for (const id of ids) {
        stmts.deleteMailboxSingle.run(id);
        count++;
      }
      return count;
    },

    pruneExpiredMailbox(maxAgeMs = 14 * 24 * 60 * 60 * 1000) {
      const cutoff = Date.now() - maxAgeMs;
      stmts.pruneMailbox.run(cutoff);
    },

    close() {
      if (closed) return;
      closed = true;
      db.close();
    }
  };
}
