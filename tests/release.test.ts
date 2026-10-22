import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, copyFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { verifyRelease } from '../apps/client/src/release.js';
import { Artifacts, windowsConnectionPackage, type ClientArtifact } from '../apps/server/src/artifacts.js';
import { zipSync, unzipSync } from 'fflate';
import { buildSync } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { windowsEnvironment } from '../apps/client/src/windows.js';
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

const boot = () => ({ v: 1 as const, sessionId: randomUUID(), enrollmentId: randomUUID(), instanceId: randomUUID(), epoch: randomUUID(), origin: 'https://example.invalid:5116', bootstrapKey: 'a'.repeat(43), expiresAt: new Date(Date.now() + 600000).toISOString() });
const winArtifact = (archive: Buffer, manifest: Buffer): ClientArtifact => ({ platform: 'win32', arch: 'x64', version: VERSION, filename: `nyaarink-client-${VERSION}-win32-x64.zip`, sha256: sha(archive), manifestSha256: sha(manifest) });
it('builds a transparent ZIP with separate session credentials and an unchanged runtime archive', () => {
  const archive = Buffer.from(zipSync({ 'fixture.txt': Buffer.from('signed runtime fixture') })), input = boot();
  const artifact = winArtifact(archive, Buffer.from('manifest'));
  const packed = unzipSync(windowsConnectionPackage(input, artifact, archive));
  const prefix = `NyaaRink-${input.sessionId}/`;
  expect(Object.keys(packed).every(name => name.startsWith(prefix) && name.split('/').length === 2)).toBe(true);
  const entries = Object.fromEntries(Object.entries(packed).map(([name, data]) => [name.slice(prefix.length), data]));
  expect(Object.keys(entries).sort()).toEqual(['README.txt', 'bootstrap.json', 'client-runtime.zip', 'start.bat']);
  expect(JSON.parse(Buffer.from(entries['bootstrap.json']!).toString())).toEqual(input);
  expect(Buffer.from(entries['client-runtime.zip']!)).toEqual(archive);
  const bat = Buffer.from(entries['start.bat']!).toString();
  expect(bat).not.toMatch(/EncodedCommand|Invoke-WebRequest|ExecutionPolicy|https:|bootstrapKey/);
  expect(bat).not.toContain(input.bootstrapKey); expect(bat).toContain('AccessControlSections]::Access');
  expect(bat).toContain(artifact.sha256); expect(bat).toContain(artifact.manifestSha256);
  expect(Buffer.from(entries['README.txt']!).toString()).toContain('AI Agent');
  expect(() => windowsConnectionPackage(input, artifact, Buffer.from('changed'))).toThrow('hash');
});
it.skipIf(process.platform !== 'win32')('runs the BAT from a Chinese space path and blocks package/signature tampering before installation', () => {
  const { path, pair, key } = fixture();
  const source = new URL('../apps/client/src/release.ts', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const verifier = buildSync({ stdin: { contents: `import { verifyRelease } from ${JSON.stringify(source)}; verifyRelease(process.argv[2], process.argv[3], 'win32', ${JSON.stringify(key)});`, resolveDir: process.cwd() }, bundle: true, platform: 'node', format: 'cjs', write: false }).outputFiles[0]!.contents;
  copyFileSync(process.execPath, join(path, 'node.exe'));
  writeFileSync(join(path, 'verify.cjs'), verifier);
  // Safe installation sentinel: never touches SSH, autorun or real credentials.
  writeFileSync(join(path, 'client.cjs'), "require('node:fs').writeFileSync(process.env.NR_TEST_INSTALLED, process.argv.slice(2).join(' '))");
  const names = ['node.exe', 'verify.cjs', 'client.cjs', 'LICENSE', 'NODE-LICENSE', 'THIRD-PARTY-NOTICES'];
  const files = Object.fromEntries(names.map(name => [name, readFileSync(join(path, name))]));
  const manifest = Buffer.from(JSON.stringify({ v: 1, version: VERSION, platform: 'win32', arch: 'x64', nodeVersion: process.versions.node, minimumSystem: 'test fixture', files: Object.fromEntries(names.map(name => [name, sha(files[name]!)])) }));
  const signature = sign(null, manifest, pair.privateKey);
  const runtime = { ...files, 'manifest.json': manifest, 'manifest.sig': signature };
  const archive = Buffer.from(zipSync(runtime, { level: 1 })), artifact = winArtifact(archive, manifest);
  const before = readdirSync(process.env.LOCALAPPDATA!).filter(name => name.startsWith('NyaaRink-bootstrap-')).sort();
  const run = (label: string, pack: Buffer, expected: number) => {
    const target = join(directory(), `中文 空格 & ${label}`);
    const entries = unzipSync(pack);
    mkdirSync(target);
    for (const [name, bytes] of Object.entries(entries)) { const path = join(target, name); mkdirSync(join(path, '..'), { recursive: true }); writeFileSync(path, bytes); }
    const folders = readdirSync(target); expect(folders).toHaveLength(1);
    const packageDirectory = join(target, folders[0]!);
    const marker = join(target, 'installed.txt');
    const result = spawnSync('cmd.exe', ['/d', '/c', 'start.bat'], { cwd: packageDirectory, input: '\r\n', windowsHide: true, timeout: 60000, env: windowsEnvironment({ ...process.env, NR_TEST_INSTALLED: marker }), encoding: 'utf8' });
    expect(result.error).toBeUndefined(); expect(result.status, result.stderr).toBe(expected);
    expect(existsSync(marker)).toBe(expected === 0);
    if (expected === 0) expect(readFileSync(marker, 'utf8')).toContain('install --bootstrap');
  };
  run('正常', windowsConnectionPackage(boot(), artifact, archive), 0);
  const brokenEntries = unzipSync(windowsConnectionPackage(boot(), artifact, archive));
  const archiveEntry = Object.keys(brokenEntries).find(name => name.endsWith('/client-runtime.zip'))!; brokenEntries[archiveEntry] = Buffer.from('changed');
  run('包篡改', Buffer.from(zipSync(brokenEntries, { level: 0 })), 1);
  const badSignature = Buffer.from(signature); badSignature[0] = badSignature[0]! ^ 1;
  const badArchive = Buffer.from(zipSync({ ...runtime, 'manifest.sig': badSignature }, { level: 1 }));
  run('签名篡改', windowsConnectionPackage(boot(), winArtifact(badArchive, manifest), badArchive), 1);
  expect(readdirSync(process.env.LOCALAPPDATA!).filter(name => name.startsWith('NyaaRink-bootstrap-')).sort()).toEqual(before);
}, 180000);
