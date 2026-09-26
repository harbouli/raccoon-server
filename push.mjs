import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function resolveServiceAccount(customPath) {
  // 1. Direct path or JSON string in environment variable
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const raw = process.env.FIREBASE_SERVICE_ACCOUNT.trim();
      if (raw.startsWith('{')) {
        return JSON.parse(raw);
      }
      if (existsSync(raw)) {
        return JSON.parse(readFileSync(raw, 'utf8'));
      }
    } catch (err) {
      console.warn('[push] Failed to parse FIREBASE_SERVICE_ACCOUNT env:', err.message);
    }
  }

  // 2. Standard GOOGLE_APPLICATION_CREDENTIALS
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    const gPath = process.env.GOOGLE_APPLICATION_CREDENTIALS.trim();
    if (existsSync(gPath)) {
      try {
        return JSON.parse(readFileSync(gPath, 'utf8'));
      } catch (err) {
        console.warn('[push] Failed to parse GOOGLE_APPLICATION_CREDENTIALS file:', err.message);
      }
    }
  }

  // 3. Custom path parameter
  if (customPath && existsSync(customPath)) {
    try {
      return JSON.parse(readFileSync(customPath, 'utf8'));
    } catch (err) {
      console.warn(`[push] Failed to parse credentials at ${customPath}:`, err.message);
    }
  }

  // 4. Default project file locations
  const searchCandidates = [
    resolve(__dirname, 'serviceAccountKey.json'),
    resolve(__dirname, 'firebase-service-account.json'),
    resolve(__dirname, 'config', 'serviceAccountKey.json'),
    resolve(__dirname, 'config', 'firebase-service-account.json'),
  ];

  for (const candidate of searchCandidates) {
    if (existsSync(candidate)) {
      try {
        return JSON.parse(readFileSync(candidate, 'utf8'));
      } catch (err) {
        console.warn(`[push] Error reading candidate ${candidate}:`, err.message);
      }
    }
  }

  // 5. Look for any *-firebase-adminsdk-*.json in project directory
  try {
    const files = readdirSync(__dirname);
    for (const file of files) {
      if (file.endsWith('.json') && file.includes('firebase-adminsdk')) {
        const fullPath = resolve(__dirname, file);
        return JSON.parse(readFileSync(fullPath, 'utf8'));
      }
    }
  } catch (err) {
    console.warn('[push] Error scanning directory for firebase-adminsdk:', err.message);
  }

  return null;
}

export function createPushService({
  db,
  isDev = process.env.NODE_ENV !== 'production',
  serviceAccountPath = null,
  enableFcm = process.env.NODE_ENV !== 'test',
} = {}) {
  const dispatches = [];
  let isFcmReady = false;
  let projectId = null;
  let messagingInstance = null;

  if (enableFcm) {
    const credentials = resolveServiceAccount(serviceAccountPath);
    if (credentials) {
      try {
        let app;
        if (getApps().length === 0) {
          app = initializeApp({
            credential: cert(credentials),
          });
        } else {
          app = getApps()[0];
        }
        messagingInstance = getMessaging(app);
        isFcmReady = true;
        projectId = credentials.project_id || app.options.projectId;
        console.log(`[push] Firebase Admin initialized successfully for project: ${projectId}`);
      } catch (error) {
        console.warn('[push] Error initializing Firebase Admin:', error.message);
      }
    }
  }

  return {
    isFcmEnabled() {
      return isFcmReady;
    },

    getProjectId() {
      return projectId;
    },

    getDispatches() {
      return [...dispatches];
    },

    clearDispatches() {
      dispatches.length = 0;
    },

    /**
     * Send push notification directly to an FCM registration token.
     */
    async sendToToken({ platform = 'android', token, title, body, data = {} }) {
      const stringData = Object.fromEntries(
        Object.entries(data).map(([k, v]) => [k, String(v)])
      );

      const item = {
        platform,
        token,
        title,
        body,
        data: stringData,
        dispatchedAt: Date.now(),
      };
      dispatches.push(item);

      if (isFcmReady && messagingInstance) {
        try {
          const message = {
            token,
            notification: {
              title,
              body,
            },
            data: stringData,
            android: {
              priority: 'high',
              notification: {
                sound: 'default',
                priority: 'high',
                channelId: 'raccoon_messages',
              },
            },
            apns: {
              headers: {
                'apns-priority': '10',
              },
              payload: {
                aps: {
                  alert: {
                    title,
                    body,
                  },
                  sound: 'default',
                  badge: 1,
                  contentAvailable: true,
                },
              },
            },
          };

          const response = await messagingInstance.send(message);
          return { ok: true, messageId: response };
        } catch (error) {
          console.warn(`[push] FCM delivery failed for ${platform} token ${token.slice(0, 10)}...:`, error.message);
          const isInvalidToken =
            error.code === 'messaging/registration-token-not-registered' ||
            error.code === 'messaging/invalid-registration-token' ||
            error.code === 'messaging/invalid-argument';

          return { ok: false, error: error.message, isInvalidToken };
        }
      }

      // Local mock logging fallback
      if (isDev) {
        process.stdout.write(
          `[PUSH DISPATCH] to ${platform}:${token.slice(0, 8)}... "${title}" - "${body}"\n`
        );
      }
      return { ok: true, mock: true };
    },

    /**
     * Dispatch notification to all registered tokens for a given public ID.
     */
    async dispatchToPublicId(publicId, { title, body, data = {} }) {
      if (!db) return [];
      const tokens = db.getDeviceTokens(publicId);
      if (!tokens || tokens.length === 0) return [];

      const results = [];
      for (const { platform, token } of tokens) {
        const sendResult = await this.sendToToken({
          platform,
          token,
          title,
          body,
          data,
        });

        if (sendResult.isInvalidToken) {
          // Auto-clean stale or unregistered token from SQLite database
          console.log(`[push] Removing stale ${platform} token for ${publicId.slice(0, 8)}...`);
          db.removeDeviceToken(publicId, platform);
        }

        results.push({
          recipientPublicId: publicId,
          platform,
          token,
          ...sendResult,
        });
      }
      return results;
    },
  };
}
