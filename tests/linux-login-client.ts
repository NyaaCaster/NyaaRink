// Invoked only inside the explicitly provisioned disposable ordinary account.
import { strict as assert } from 'node:assert';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { install, installHooks } from '../apps/client/src/install.js';
import { StateStore } from '../apps/client/src/state.js';
import { Bootstrap } from '../packages/contracts/device.js';

async function main() {
  assert.equal(process.platform, 'linux'); assert.match(userInfo().username, /^nrtest[0-9a-f]+$/);
  const runtime = process.env.NR_TEST_RUNTIME!;
  const input = JSON.parse(readFileSync(join(runtime, 'input.json'), 'utf8'));
  const bootstrap = Bootstrap.parse(input.bootstrap), store = new StateStore(bootstrap.sessionId);
  const original = readFileSync(join(homedir(), '.ssh', 'authorized_keys'), 'utf8');
  const state = await install(bootstrap, store, runtime, installHooks(async () => true, Number(process.argv[2])));
  assert.equal(state.phase, 'ready');
  // Only this test unit trusts the ephemeral CA; never change the machine trust store.
  const dropin = state.loginFile! + '.d'; mkdirSync(dropin, { mode: 0o700 });
  writeFileSync(join(dropin, 'test-ca.conf'), '[Service]\nEnvironment=NODE_EXTRA_CA_CERTS=' + join(runtime, 'cert.pem') + '\n', { mode: 0o600 });
  writeFileSync(join(runtime, 'original-keys'), original, { mode: 0o600 });
  console.log(JSON.stringify({ loginRecoveryPrepared: true, sessionId: bootstrap.sessionId }));
}
main().catch(() => { console.error('Disposable login preparation failed'); process.exitCode = 1; });
