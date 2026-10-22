// Executed only inside an explicitly provisioned disposable ordinary account.
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir, userInfo, homedir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { utils } from 'ssh2';
import { localSsh, verifyLoopback, privilegedAccount, installLogin, removeLogin } from '../apps/client/src/platform.js';
import { changeKey } from '../apps/client/src/keys.js';
import { deviceKeys, StateStore, type State } from '../apps/client/src/state.js';
import { token } from '../apps/server/src/crypto.js';

async function main() {
  assert.match(userInfo().username, /^nrtest[0-9a-f]+$/); assert.equal(privilegedAccount(), false);
  if (process.platform === 'win32') {
    const fixture = join(homedir(), '.ssh'); mkdirSync(fixture, { recursive: true });
    if (!existsSync(join(fixture, 'authorized_keys'))) writeFileSync(join(fixture, 'authorized_keys'), '# disposable fixture\r\n');
  }
  const local = await localSsh(Number(process.argv[2]), async () => true);
  await verifyLoopback(local.host, local.port, local.hostKeys);
  const directory = mkdtempSync(join(tmpdir(), 'nyaarink-native-'));
  const sessionId = randomUUID(), pair = deviceKeys();
  const store = new StateStore(sessionId, directory);
  const state: State = { v: 1, phase: 'ready', devicePrivateKey: pair.privateKey, devicePublicKey: pair.publicKey,
    bootstrap: { v: 1, sessionId, enrollmentId: randomUUID(), instanceId: randomUUID(), epoch: randomUUID(), origin: 'https://example.invalid:5116', bootstrapKey: token(), expiresAt: new Date().toISOString() },
    runtime: process.env.NR_TEST_RUNTIME!, cleanup: 'pending', reported: false, releaseVersion: '0.1.0' };
  const original = readFileSync(local.authorizedKeys, 'utf8'), key = utils.generateKeyPairSync('ed25519', {}).public;
  try {
    store.write(state); assert.equal(store.read().phase, 'ready');
    changeKey(local.authorizedKeys, sessionId, key, true); changeKey(local.authorizedKeys, sessionId, key, false);
    assert.equal(readFileSync(local.authorizedKeys, 'utf8'), original);
    state.loginFile = installLogin(state, store.directory); store.write(state);
    console.log(JSON.stringify({ account: local.account, platform: local.platform, port: local.port, privateState: true, hostPin: true, originalKeysPreserved: true, loginRegistration: true }));
  } finally {
    try { if (state.loginFile) removeLogin(state); }
    finally {
      // The fixture owns this file, even if login registration failed.
      writeFileSync(local.authorizedKeys, original, { mode: 0o600 });
      rmSync(directory, { recursive: true, force: true });
    }
  }
}
main().catch(error => { console.error(error instanceof Error ? error.message : 'native check failed'); process.exitCode = 1; });
