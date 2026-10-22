import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { verifyRelease } from '../apps/client/src/release.js';
import { Artifacts } from '../apps/server/src/artifacts.js';
import { VERSION } from '@nyaarink/version';

const roots: string[] = [];
afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { force: true, recursive: true }); });
function directory() { const path = mkdtempSync(join(tmpdir(), 'nyaarink-release-')); roots.push(path); return path; }
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
function fixture() {
  const path = directory(), pair = generateKeyPairSync('ed25519');
  const key = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const files: Record<string, string> = {};
  for (const name of ['client.cjs', 'verify.cjs', process.platform === 'win32' ? 'node.exe' : 'node', 'NODE-LICENSE', 'LICENSE', 'THIRD-PARTY-NOTICES']) {
    writeFileSync(join(path, name), name); files[name] = sha(name);
  }
  const text = JSON.stringify({ v: 1, version: VERSION, platform: process.platform, arch: process.arch, nodeVersion: process.versions.node, minimumSystem: 'test fixture', files });
  writeFileSync(join(path, 'manifest.json'), text); writeFileSync(join(path, 'manifest.sig'), sign(null, Buffer.from(text), pair.privateKey));
  return { path, pair, key };
}
describe('offline signed distribution boundary', () => {
  it('accepts a complete signature and rejects file tampering, extra files and stale versions', () => {
    const { path, key } = fixture();
    expect(verifyRelease(path, VERSION, process.platform, key).version).toBe(VERSION);
    expect(() => verifyRelease(path, '0.0.0', process.platform, key)).toThrow('version');
    writeFileSync(join(path, 'extra.cjs'), 'untrusted');
    expect(() => verifyRelease(path, VERSION, process.platform, key)).toThrow('Unexpected');
    rmSync(join(path, 'extra.cjs')); writeFileSync(join(path, 'client.cjs'), 'changed');
    expect(() => verifyRelease(path, VERSION, process.platform, key)).toThrow('file rejected');
  });
  it('rejects a substituted signing key and modified manifest', () => {
    const { path, key } = fixture(), other = generateKeyPairSync('ed25519');
    expect(() => verifyRelease(path, VERSION, process.platform, other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'))).toThrow('signature');
    writeFileSync(join(path, 'manifest.json'), readFileSync(join(path, 'manifest.json'), 'utf8') + ' ');
    expect(() => verifyRelease(path, VERSION, process.platform, key)).toThrow('signature');
  });
  it('validates the signed two-platform catalog and rejects changed downloadable archives', () => {
    const { path, pair, key } = fixture();
    const artifacts = (['win32', 'linux'] as const).map(platform => {
      const filename = `nyaarink-client-${VERSION}-${platform}-x64.${platform === 'win32' ? 'zip' : 'tar.gz'}`;
      writeFileSync(join(path, filename), platform);
      return { platform, arch: 'x64', version: VERSION, filename, sha256: sha(platform), manifestSha256: 'b'.repeat(64) };
    });
    const text = JSON.stringify({ v: 1, version: VERSION, artifacts });
    writeFileSync(join(path, 'index.json'), text); writeFileSync(join(path, 'index.sig'), sign(null, Buffer.from(text), pair.privateKey));
    expect(new Artifacts(path, key).get('linux').filename).toBe(artifacts[1]!.filename);
    writeFileSync(join(path, artifacts[0]!.filename), 'changed');
    expect(() => new Artifacts(path, key)).toThrow('hash');
  });
});
