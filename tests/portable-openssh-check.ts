// Explicit opt-in system check: isolated loopback daemon, no service changes.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { Client, utils } from 'ssh2';
import { keyLine } from '../apps/client/src/keys.js';
import { privatePath } from '../apps/client/src/state.js';
import { randomUUID } from 'node:crypto';

async function main() {
  assert.equal(process.platform, 'win32');
  const directory = mkdtempSync(join(tmpdir(), 'nyaarink-ssh-compat-'));
  privatePath(directory);
  const host = join(directory, 'host'), keys = join(directory, 'authorized_keys');
  const config = join(directory, 'sshd_config'), key = utils.generateKeyPairSync('ed25519', {});
  let daemon: ReturnType<typeof spawn> | undefined;
  const clients = new Set<Client>(); let log = '';
  try {
    const socket = createServer(); await new Promise<void>(ok => socket.listen(0, '127.0.0.1', ok));
    const address = socket.address(); assert(address && typeof address === 'object'); const port = address.port;
    await new Promise<void>(ok => socket.close(() => ok()));
    const sshDirectory = process.env.NYAARINK_PORTABLE_SSH!;
    execFileSync(join(sshDirectory, 'ssh-keygen.exe'), ['-q', '-t', 'ed25519', '-N', '', '-f', host], { windowsHide: true });
    writeFileSync(keys, keyLine(randomUUID(), key.public) + '\n'); privatePath(keys);
    const path = (value: string) => '"' + value.replaceAll('\\', '/') + '"';
    writeFileSync(config, `Port ${port}\nListenAddress 127.0.0.1\nHostKey ${path(host)}\nAuthorizedKeysFile ${path(keys)}\nPubkeyAuthentication yes\nPasswordAuthentication no\nPermitTTY yes\nStrictModes yes\nSubsystem sftp ${path(join(sshDirectory, 'sftp-server.exe'))}\n`);
    const effective = execFileSync(join(process.env.NYAARINK_PORTABLE_SSH!, 'sshd.exe'), ['-T', '-f', config], { encoding: 'utf8', windowsHide: true });
    console.log(effective.split('\n').filter(line => /port |pubkeyauthentication|passwordauthentication|permittty|subsystem|pubkeyacceptedalgorithms|listenaddress/.test(line)).join('\n'));
    const hostKey = utils.parseKey(execFileSync(join(sshDirectory, 'ssh-keygen.exe'), ['-y', '-f', host]));
    assert(!(hostKey instanceof Error) && !Array.isArray(hostKey));
    daemon = spawn(join(process.env.NYAARINK_PORTABLE_SSH!, 'sshd.exe'), ['-D', '-e', '-f', config], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    daemon.stderr!.on('data', data => { log = (log + data).slice(-12000); });
    const connect = () => new Promise<Client>((ok, fail) => {
      const client = new Client(); clients.add(client);
      // Keep the listener during teardown: an authentication failure can be
      // followed by a socket reset when the isolated daemon is terminated.
      client.on('error', fail).once('ready', () => ok(client));
      client.connect({ host: '127.0.0.1', port, username: userInfo().username, privateKey: key.private, readyTimeout: 5000,
        hostVerifier: (raw: Buffer) => raw.equals(hostKey.getPublicSSH()) });
    });
    let client: Client | undefined;
    for (let attempt = 0; attempt < 20; attempt++) {
      try { client = await connect(); break; } catch { await new Promise(ok => setTimeout(ok, 150)); }
    }
    assert(client, 'isolated SSH authentication failed: ' + log);
    const command = (pty: boolean) => new Promise<void>((ok, fail) => {
      client!.exec('cmd.exe /d /c echo NYAARINK_COMPAT_OK', { pty }, (error, stream) => {
        if (error) { fail(error); return; } let output = '';
        stream.on('data', (data: Buffer) => { output += data; });
        stream.on('error', fail).on('close', () => { try { assert(output.includes('NYAARINK_COMPAT_OK')); ok(); } catch (error) { fail(error); } });
      });
    });
    await command(false); await command(true);
    await new Promise<void>((ok, fail) => client!.sftp((error, sftp) => {
      if (error) { fail(error); return; }
      sftp.stat(keys.replaceAll('\\', '/'), (error, stats) => { sftp.end(); if (error) fail(error); else { assert(stats.isFile()); ok(); } });
    }));
    await new Promise<void>((ok, fail) => client!.forwardOut('127.0.0.1', 12345, '127.0.0.1', port, (error, channel) => {
      if (error) ok(); else { channel.destroy(); fail(new Error('restrict did not deny direct forwarding')); }
    }));
    await new Promise<void>((ok, fail) => client!.forwardIn('127.0.0.1', 0, error => error ? ok() : fail(new Error('restrict did not deny remote forwarding'))));
    client.end();
    writeFileSync(keys, '');
    await assert.rejects(connect(), /authentication methods failed/);
    console.log(JSON.stringify({ version: '10.4.0.0p1-Preview', portable: true, isolated: true, hostPin: true, ed25519: true, exec: true, pty: true, sftp: true, directForwardDenied: true, remoteForwardDenied: true, removedKeyDenied: true, ordinaryAccount: false }));
  } finally {
    for (const client of clients) client.destroy();
    if (daemon && daemon.exitCode === null) {
      const exited = new Promise<void>(ok => daemon!.once('exit', () => ok())); daemon.kill(); await exited;
    }
    rmSync(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
