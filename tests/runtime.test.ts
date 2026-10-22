import { afterEach, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VERSION } from '@nyaarink/version';
import { installRuntime } from '../apps/client/src/runtime.js';

const testKey = vi.hoisted(() => ({ value: '' }));
vi.mock('../apps/client/src/release.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../apps/client/src/release.js')>();
  return { ...actual, verifyRelease: (path: string, version: string) => actual.verifyRelease(path, version, process.platform, testKey.value) };
});
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
it('installs signed same-version fixes separately, preserves legacy runtimes and rejects a corrupted installed copy', () => {
  const root = mkdtempSync(join(tmpdir(), 'nyaarink-runtime-')); roots.push(root);
  const pair = generateKeyPairSync('ed25519'); testKey.value = pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const fixture = (label: string) => {
    const source = join(root, label); mkdirSync(source);
    const files: Record<string, string> = {};
    for (const name of ['client.cjs', 'verify.cjs', process.platform === 'win32' ? 'node.exe' : 'node', 'NODE-LICENSE', 'LICENSE', 'THIRD-PARTY-NOTICES']) {
      const data = label + name; writeFileSync(join(source, name), data); files[name] = createHash('sha256').update(data).digest('hex');
    }
    const manifest = Buffer.from(JSON.stringify({ v: 1, version: VERSION, platform: process.platform, arch: 'x64', nodeVersion: process.versions.node, minimumSystem: 'test', files }));
    writeFileSync(join(source, 'manifest.json'), manifest); writeFileSync(join(source, 'manifest.sig'), sign(null, manifest, pair.privateKey)); return source;
  };
  const destination = join(root, 'installed'); mkdirSync(destination);
  const legacy = join(destination, `runtime-${VERSION}-${process.platform}-${process.arch}`); mkdirSync(legacy); writeFileSync(join(legacy, 'existing-session'), 'retained');
  const first = fixture('old'), second = fixture('fix');
  const old = installRuntime(first, destination), fixed = installRuntime(second, destination);
  expect(old).not.toBe(fixed); expect(installRuntime(second, destination)).toBe(fixed);
  expect(existsSync(join(legacy, 'existing-session'))).toBe(true); expect(existsSync(old)).toBe(true);
  writeFileSync(join(fixed, 'client.cjs'), 'corruption');
  expect(() => installRuntime(second, destination)).toThrow('file rejected');
}, 60000);
