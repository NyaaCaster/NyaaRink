// Explicit Linux check: isolated daemon and temporary keys, no service changes.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { connect, createServer } from 'node:net';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { NativeSSH } from '../apps/server/src/proxy.js';
import type { TunnelHub } from '../apps/server/src/tunnel.js';

async function main() {
  assert.equal(process.platform, 'linux');
  const root = mkdtempSync(join(homedir(), '.nr-check-')), id = randomUUID();
  let daemon: ReturnType<typeof spawn> | undefined, native: NativeSSH | undefined;
  const sockets = new Set<ReturnType<typeof connect>>();
  try {
    const probe = createServer(); await new Promise<void>(ok => probe.listen(0, '127.0.0.1', ok));
    const port = (probe.address() as { port: number }).port; await new Promise<void>(ok => probe.close(() => ok()));
    for (const name of ['host', 'identity']) execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(root, name)]);
    writeFileSync(join(root, 'authorized_keys'), 'restrict,pty ' + readFileSync(join(root, 'identity.pub'), 'utf8'), { mode: 0o600 });
    writeFileSync(join(root, 'sshd_config'), `Port ${port}\nListenAddress 127.0.0.1\nHostKey ${root}/host\nAuthorizedKeysFile ${root}/authorized_keys\nStrictModes yes\nPubkeyAuthentication yes\nPasswordAuthentication no\nPermitRootLogin prohibit-password\nUsePAM no\nSubsystem sftp internal-sftp\n`);
    daemon = spawn('/usr/sbin/sshd', ['-D', '-e', '-f', join(root, 'sshd_config')], { stdio: 'ignore' });
    let ready = false;
    for (let n = 0; n < 30; n++) {
      ready = await new Promise<boolean>(ok => { const socket = connect(port, '127.0.0.1'); socket.once('connect', () => { socket.destroy(); ok(true); }); socket.on('error', () => ok(false)); });
      if (ready) break; await new Promise(ok => setTimeout(ok, 100));
    }
    assert(ready, 'isolated daemon unavailable');
    let active = true;
    const service = Object.assign(new EventEmitter(), {
      sessions: new Map([[id, {}]]), activeSummary: () => { if (!active) throw new Error('revoked'); },
      credentials: () => ({ sshPrivate: readFileSync(join(root, 'identity'), 'utf8'), device: { account: userInfo().username, hostKeys: [readFileSync(join(root, 'host.pub'), 'utf8').split(' ')[1]!] } }),
    });
    const hub = { service, open: () => { service.activeSummary(); const socket = connect(port, '127.0.0.1'); sockets.add(socket); socket.once('close', () => sockets.delete(socket)); return socket; } } as unknown as TunnelHub;
    native = new NativeSSH(hub, join(root, 'run'), process.argv[2]!);
    const config = await native.get(id);
    const result = await new Promise<string>((ok, fail) => {
      const command = spawn('ssh', ['-F', config.configPath, config.host, 'printf NYAARINK_NATIVE_OK'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '', error = ''; const timer = setTimeout(() => { command.kill(); fail(new Error('native timeout')); }, 15000);
      command.stdout.on('data', chunk => output += chunk); command.stderr.on('data', chunk => error += chunk);
      command.once('error', fail); command.once('exit', code => { clearTimeout(timer); if (code === 0) ok(output); else fail(new Error(error)); });
    });
    assert.equal(result, 'NYAARINK_NATIVE_OK');
    active = false; service.emit('cleanup', id);
    assert.equal(existsSync(config.configPath), false);
    await assert.rejects(native.get(id), /revoked/);
    console.log(JSON.stringify({ nativeOpenSSH: true, isolatedDaemon: true, hostPin: true, cleanup: true, account: userInfo().uid === 0 ? 'root-test-only' : 'ordinary' }));
  } finally {
    native?.close(); for (const socket of sockets) socket.destroy();
    if (daemon && daemon.exitCode === null) { const stopped = new Promise<void>(ok => daemon!.once('exit', () => ok())); daemon.kill(); await stopped; }
    rmSync(root, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
