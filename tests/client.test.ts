import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { utils } from 'ssh2';
import { install, localRevoke, type InstallHooks } from '../apps/client/src/install.js';
import { StateStore, deviceKeys, type State } from '../apps/client/src/state.js';
import { changeKey, keyLine } from '../apps/client/src/keys.js';
import { DeviceApi } from '../apps/client/src/api.js';
import { token } from '../apps/server/src/crypto.js';
import { connectionScript } from '../apps/server/src/artifacts.js';
import type { BootstrapData } from '../packages/contracts/device.js';
import { supportedSshVersion } from '../apps/client/src/platform.js';
import { windowsInspectionScript } from '../apps/client/src/windows-inspection.js';
import { windowsEnvironment } from '../apps/client/src/windows.js';

const roots: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function root() { const path = mkdtempSync(join(tmpdir(), 'nyaarink-client-')); roots.push(path); return path; }
function bootstrap(): BootstrapData { return { v: 1, sessionId: randomUUID(), enrollmentId: randomUUID(), instanceId: randomUUID(), epoch: randomUUID(), origin: 'https://example.invalid:5116', bootstrapKey: token(), expiresAt: new Date(Date.now() + 600000).toISOString() }; }
function state(boot: BootstrapData): State { const pair = deviceKeys(); return { v: 1, bootstrap: boot, phase: 'ready', devicePrivateKey: pair.privateKey, devicePublicKey: pair.publicKey, runtime: root(), cleanup: 'pending', reported: false, releaseVersion: '0.1.0' }; }
const ssh = () => utils.generateKeyPairSync('ed25519', {}).public;
describe('C installation and irreversible cleanup', () => {
  it('limits UAC inspection to the fixed sshd command for the original account', () => {
    const script = windowsInspectionScript('ordinary.user', 22142);
    expect(script).toContain('-Verb RunAs'); expect(script).toContain('PipeSecurity');
    expect(script).not.toContain('bootstrap');
    const encoded = /EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(script)![1]!;
    const child = Buffer.from(encoded, 'base64').toString('utf16le');
    expect(child).toContain('TokenImpersonationLevel]::Anonymous');
    expect(child).toContain('OpenSSH\\sshd.exe');
    expect(child).toContain('-T -C \'user=ordinary.user,'); expect(child).toContain('lport=22142');
    expect(child).not.toMatch(/client\.cjs|Set-Acl|Start-Service|Add-WindowsCapability/);
    for (const account of ["user'; Start-Process cmd; '", 'user\nroot', 'user,host=other']) expect(() => windowsInspectionScript(account, 22)).toThrow('Unsafe');
    expect(() => windowsInspectionScript('ordinary', 0)).toThrow('Unsafe');
    expect(() => windowsInspectionScript('ordinary', 65536)).toThrow('Unsafe');
  });
  it.skipIf(process.platform !== 'win32')('parses both PowerShell scripts and exercises the real pipe without elevation', () => {
    const script = windowsInspectionScript('ordinary.user', 22142);
    const child = Buffer.from(/EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(script)![1]!, 'base64').toString('utf16le');
    for (const source of [script, child]) {
      const encoded = Buffer.from(source, 'utf16le').toString('base64');
      const parser = `$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encoded}')),[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)}`;
      execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', parser], { env: windowsEnvironment(), windowsHide: true, timeout: 10000 });
    }
    // Exercise real Windows pipe ACLs and anonymous client transport, while
    // deliberately avoiding UAC or any change to the existing SSH service.
    const transport = script.replace('-Verb RunAs ', '');
    const response = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(transport, 'utf16le').toString('base64')], { env: windowsEnvironment(), windowsHide: true, encoding: 'utf8', timeout: 60000 });
    expect(typeof JSON.parse(response).ok).toBe('boolean');
  }, 90000);
  it('enforces the approved OpenSSH minimum for both platforms', () => {
    expect(supportedSshVersion('OpenSSH_for_Windows_8.6p1, LibreSSL')).toBe(false);
    expect(supportedSshVersion('OpenSSH_8.9p1 Ubuntu')).toBe(true);
    expect(supportedSshVersion('OpenSSH_for_Windows_9.8p1')).toBe(true);
    expect(supportedSshVersion('unrecognized daemon')).toBe(false);
  });
  it('preserves other SSH lines and removes exactly one session key', () => {
    const file = join(root(), 'authorized_keys'), original = '# original\n' + ssh() + '\n';
    writeFileSync(file, original, { mode: 0o600 }); const id = randomUUID(), key = ssh();
    changeKey(file, id, key, true); changeKey(file, id, key, true);
    expect(readFileSync(file, 'utf8')).toBe(original + keyLine(id, key) + '\n');
    changeKey(file, id, key, false); expect(readFileSync(file, 'utf8')).toBe(original);
    expect(existsSync(file + '.nyaarink.lock')).toBe(false);
  });
  it('rejects a conflicting marker without changing the original file', () => {
    const file = join(root(), 'authorized_keys'), id = randomUUID();
    const original = keyLine(id, ssh()) + '\n'; writeFileSync(file, original, { mode: 0o600 });
    expect(() => changeKey(file, id, ssh(), true)).toThrow('Conflicting'); expect(readFileSync(file, 'utf8')).toBe(original);
  });
  it('offline revoke preserves cleanup runner and cannot be overwritten by stale ready state', async () => {
    const boot = bootstrap(), store = new StateStore(boot.sessionId, root()), initial = state(boot); store.write(initial);
    const removeLogin = vi.fn(), addKey = vi.fn();
    const offline = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'));
    const result = await localRevoke(store, { removeLogin, addKey }, offline);
    expect(result.phase).toBe('revoked'); expect(result.cleanup).toBe('pending'); expect(removeLogin).not.toHaveBeenCalled();
    expect(result.devicePrivateKey).toBeDefined(); expect(() => store.write(initial)).toThrow('permanent');
    expect(store.read().phase).toBe('revoked');
  }, 30000);
  it('signed cleanup removes login and destroys device proof only after acknowledgment', async () => {
    const boot = bootstrap(), store = new StateStore(boot.sessionId, root()); store.write(state(boot));
    const request = vi.fn<typeof fetch>().mockImplementation(async url => Response.json(String(url).endsWith('/challenge') ? { v: 1, nonce: token(), instanceId: boot.instanceId, epoch: boot.epoch } : { ok: true }));
    const removeLogin = vi.fn(); const result = await localRevoke(store, { addKey: vi.fn(), removeLogin }, request);
    expect(result.phase).toBe('cleaned'); expect(result.devicePrivateKey).toBeUndefined(); expect(removeLogin).toHaveBeenCalledOnce();
    expect(request).toHaveBeenCalledTimes(4);
  }, 30000);
  it('a lost cleanup acknowledgment retains the login outbox and signed proof for retry', async () => {
    const boot = bootstrap(), store = new StateStore(boot.sessionId, root()); store.write(state(boot));
    const request = vi.fn<typeof fetch>().mockImplementation(async url => {
      if (String(url).endsWith('/cleanup-ack')) throw new Error('response lost');
      return Response.json(String(url).endsWith('/challenge') ? { v: 1, nonce: token(), instanceId: boot.instanceId, epoch: boot.epoch } : { ok: true });
    });
    const removeLogin = vi.fn();
    const result = await localRevoke(store, { addKey: vi.fn(), removeLogin }, request);
    expect(result.phase).toBe('revoked'); expect(result.reported).toBe(true);
    expect(result.devicePrivateKey).toBeDefined(); expect(removeLogin).not.toHaveBeenCalled();
  }, 30000);
  it('compensates failed login setup while preserving enrollment for retry', async () => {
    const boot = bootstrap(), directory = root(), store = new StateStore(boot.sessionId, directory), key = ssh();
    const addKey = vi.fn(), removeLogin = vi.fn();
    const hooks: InstallHooks = { confirm: async () => true, privileged: () => false, prepare: async () => {},
      inspect: async () => ({ account: 'ordinary', home: directory, shell: 'posix', platform: 'linux', host: '127.0.0.1', port: 22, hostKeys: [Buffer.alloc(64).toString('base64')], authorizedKeys: join(directory, 'authorized_keys') }),
      verify: async () => {}, addKey, login: () => { throw new Error('registration denied'); }, removeLogin,
      request: async () => Response.json({ v: 1, sessionId: boot.sessionId, instanceId: boot.instanceId, epoch: boot.epoch, sshPublicKey: key }) };
    await expect(install(boot, store, directory, hooks)).rejects.toThrow('registration denied');
    expect(store.read().phase).toBe('enrolled'); expect(addKey.mock.calls.map(call => call[3])).toEqual([true, false]); expect(removeLogin).toHaveBeenCalledOnce();
  }, 60000);
  it('rejects oversized API streams before reading the entire response', async () => {
    let reads = 0;
    const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(new ReadableStream({ pull(controller) { reads++; controller.enqueue(new Uint8Array(32769)); } })));
    await expect(new DeviceApi(state(bootstrap()), request).post('/api/v1/test', {})).rejects.toThrow('too large');
    expect(reads).toBeLessThan(4);
  });
  it('pins script source, package digest, manifest digest and bootstrap without management keys', () => {
    const boot = bootstrap();
    for (const platform of ['linux', 'win32'] as const) {
      const text = connectionScript(boot, { platform, arch: 'x64', version: '0.1.0', filename: `nyaarink-client-0.1.0-${platform}-x64.zip`, sha256: 'a'.repeat(64), manifestSha256: 'b'.repeat(64) });
      const decoded = platform === 'win32' ? Buffer.from(text.split('-EncodedCommand ')[1]!.split('\r\n')[0]!, 'base64').toString('utf16le') : text;
      expect(decoded).toContain(boot.origin); expect(decoded).toContain('a'.repeat(64)); expect(decoded).toContain('b'.repeat(64)); expect(decoded).not.toContain('MCP_API_KEY');
      expect(decoded).not.toMatch(/SkipCertificateCheck|curl .* -k/);
    }
  });
});
