#!/usr/bin/env node

import { createPushService } from './push.mjs';

const args = process.argv.slice(2);
function getArg(flag, defaultValue = null) {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : defaultValue;
}

const push = createPushService({ isDev: true });

console.log('--- Raccoon Push Notification Diagnostic ---');
console.log(`Firebase FCM Enabled: ${push.isFcmEnabled() ? '✅ YES' : '❌ NO (Using mock logger)'}`);
if (push.isFcmEnabled()) {
  console.log(`Firebase Project ID:  ${push.getProjectId()}`);
} else {
  console.log('\nTo enable real Firebase FCM pushes:');
  console.log('Place your Firebase Service Account JSON key as either:');
  console.log('  1) ./serviceAccountKey.json');
  console.log('  2) ./firebase-service-account.json');
  console.log('  3) export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"');
}

const targetToken = getArg('--token');
const title = getArg('--title', 'Raccoon Chat');
const body = getArg('--body', 'Test notification from Raccoon server!');

if (targetToken) {
  console.log(`\nDispatching test push to token: ${targetToken.slice(0, 16)}...`);
  const result = await push.sendToToken({
    token: targetToken,
    title,
    body,
    data: { test: 'true', timestamp: String(Date.now()) },
  });
  console.log('Dispatch result:', result);
} else {
  console.log('\nUsage to send a test push:');
  console.log('  node test-push.mjs --token <FCM_DEVICE_TOKEN> [--title "Hello"] [--body "World"]\n');
}
