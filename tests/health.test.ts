import { it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { createApp } from '../apps/server/src/app.js';
import { TunnelHub } from '../apps/server/src/tunnel.js';
import type { NativeSSH } from '../apps/server/src/proxy.js';
import { Operations } from '../apps/server/src/operations.js';
import { Files } from '../apps/server/src/files.js';
import { Shells } from '../apps/server/src/shells.js';
import type { Artifacts } from '../apps/server/src/artifacts.js';

it('only reports ready with all subsystems accepting and immediately fails closed on freeze or shutdown', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nyaarink-health-')), key = randomBytes(32);
  Authority.initialize(join(root, 'authority'), key);
  const service = await RinkService.open(new Authority(join(root, 'authority'), key), join(root, 'state'), 'https://example.invalid:5116');
  const hub = new TunnelHub(service), native = {} as NativeSSH; // Health gate only; native SSH is verified in the Linux image.
  const operations = new Operations(hub), files = new Files(hub), shells = new Shells(hub, () => true);
  let accepting = true;
  const config = { PUBLIC_BASE_URL: service.origin, MCP_API_KEY: 'x'.repeat(32), MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey: key };
  const server = createApp(service, config, {} as Artifacts, native, operations, files, shells, () => accepting).listen(0, '127.0.0.1');
  await new Promise<void>(r => server.once('listening', r));
  const origin = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
  try {
    expect((await fetch(origin + '/health/ready')).status).toBe(200);
    accepting = false;
    expect((await fetch(origin + '/health/ready')).status).toBe(503);
    accepting = true; service.authority.freeze('TEST');
    expect((await fetch(origin + '/healthz')).status).toBe(503);
    expect((await fetch(origin + '/health/live')).status).toBe(200);
  } finally {
    shells.close(); await operations.close(); await hub.close();
    server.closeAllConnections(); await new Promise<void>(r => server.close(() => r()));
    await service.close(); rmSync(root, { recursive: true, force: true });
  }
});
