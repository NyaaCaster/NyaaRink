// Opt-in production acceptance, restricted to an explicitly disposable ordinary account.
import { strict as assert } from 'node:assert';
import dns from 'node:dns';
import { readFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { install, installHooks, localRevoke } from '../apps/client/src/install.js';
import { StateStore } from '../apps/client/src/state.js';
import { runTunnel } from '../apps/client/src/tunnel.js';
import { Bootstrap } from '../packages/contracts/device.js';

async function main() {
  assert.match(userInfo().username, /^nrtest[0-9a-f]{12}$/);
  const input = JSON.parse(readFileSync(process.argv[2]!, 'utf8'));
  const bootstrap = Bootstrap.parse(input.bootstrap), hostname = new URL(bootstrap.origin).hostname;
  // This process alone resolves S to loopback; the real hostname, CA and SNI stay verified.
  const lookup = dns.lookup;
  dns.lookup = ((host: string, options: unknown, callback: unknown) => {
    if (host === hostname) return lookup('127.0.0.1', options as dns.LookupOptions, callback as never);
    return lookup(host, options as dns.LookupOptions, callback as never);
  }) as typeof dns.lookup;
  const store = new StateStore(bootstrap.sessionId);
  const hooks = installHooks(async () => true, Number(input.port));
  // Login recovery is covered by linux-account-check. This check owns foreground processes only.
  hooks.login = () => join(store.directory, 'acceptance-no-login-task');
  hooks.removeLogin = () => {};
  await install(bootstrap, store, input.runtime, hooks);
  console.log('Production client enrolled; foreground-only acceptance fixture.');
  const controller = new AbortController();
  process.once('SIGTERM', () => controller.abort());
  await runTunnel(store, () => localRevoke(store, hooks), controller.signal);
}
main().catch(() => { console.error('Production acceptance client failed'); process.exitCode = 1; });
