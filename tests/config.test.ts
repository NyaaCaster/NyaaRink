import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../apps/server/src/config.js';
import { createApp } from '../apps/server/src/app.js';
import type { Server } from 'node:http';

let root: string;
let env: NodeJS.ProcessEnv;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'nyaarink-config-'));
  for (const name of ['certs', 'state', 'authority', 'artifacts']) mkdirSync(join(root, name));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=example.invalid', '-addext', 'subjectAltName=DNS:example.invalid', '-keyout', join(root, 'certs/privkey.pem'), '-out', join(root, 'certs/fullchain.pem')], { stdio: 'ignore', env: { ...process.env, MSYS_NO_PATHCONV: '1' } });
  writeFileSync(join(root, 'master.key'), randomBytes(32));
  env = { PUBLIC_BASE_URL: 'https://example.invalid:5116', MCP_API_KEY: randomBytes(32).toString('hex'),
    TLS_CERT_DIR: join(root, 'certs'), STATE_DIR: join(root, 'state'), AUTHORITY_DIR: join(root, 'authority'),
    SESSION_MASTER_KEY_FILE: join(root, 'master.key'), CLIENT_ARTIFACT_DIR: join(root, 'artifacts') };
});
afterAll(() => { if (root) rmSync(root, { recursive: true, force: true }); });
describe('private configuration gates', () => {
  it('loads complete matching configuration', () => expect(loadConfig(env).masterKey.length).toBe(32));
  it.each(['MCP_API_KEY', 'TLS_CERT_DIR', 'SESSION_MASTER_KEY_FILE'])('refuses missing %s without leaking values', field => {
    const invalid = { ...env }; delete invalid[field];
    expect(() => loadConfig(invalid)).toThrow();
    try { loadConfig(invalid); } catch (error) { expect(String(error)).not.toContain(env.MCP_API_KEY); }
  });
  it.each(['http://example.invalid:5116', 'https://example.invalid:5115', 'https://wrong.invalid:5116', 'https://example.invalid:5116/path'])('refuses invalid origin %s', url => expect(() => loadConfig({ ...env, PUBLIC_BASE_URL: url })).toThrow());
  it('refuses shared state/authority and oversized key overlap', () => {
    expect(() => loadConfig({ ...env, AUTHORITY_DIR: env.STATE_DIR })).toThrow();
    expect(() => loadConfig({ ...env, MCP_API_KEY_PREVIOUS: env.MCP_API_KEY, API_KEY_PREVIOUS_UNTIL: new Date(Date.now() + 25 * 3600_000).toISOString() })).toThrow();
  });
});
it('health live works while unfinished skeleton refuses readiness and does not leak configuration', async () => {
  const server: Server = createApp().listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  try {
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing test port');
    const url = `http://127.0.0.1:${address.port}`;
    expect((await fetch(url + '/health/live')).status).toBe(200);
    const ready = await fetch(url + '/health/ready');
    expect(ready.status).toBe(503);
    expect(await ready.text()).not.toContain(env.MCP_API_KEY);
    expect((await fetch(url + '/unknown')).status).toBe(404);
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});
