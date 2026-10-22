import { createServer, type Server } from 'node:net';
import { chmodSync, existsSync, lstatSync, mkdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { durableWrite } from './crypto.js';
import type { TunnelHub } from './tunnel.js';

const quote = (value: string) => {
  if (/[\r\n\0"%]/.test(value)) throw new Error('Unsafe SSH configuration value');
  return '"' + value.replaceAll('\\', '\\\\') + '"';
};
export function sshFiles(id: string, account: string, keys: string[], directory: string, helper: string) {
  z.uuid().parse(id);
  return {
    known: keys.map(key => {
      const data = Buffer.from(key, 'base64'), length = data.readUInt32BE();
      const algorithm = data.subarray(4, 4 + length).toString();
      if (!/^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))$/.test(algorithm)) throw new Error('Unsupported host key');
      return `nr-${id} ${algorithm} ${key}\n`;
    }).join(''),
    config: `Host nr-${id}\n  HostName nr-${id}\n  User ${quote(account)}\n  IdentityFile ${quote(join(directory, 'identity'))}\n  IdentitiesOnly yes\n  IdentityAgent none\n  PreferredAuthentications publickey\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  StrictHostKeyChecking yes\n  UserKnownHostsFile ${quote(join(directory, 'known_hosts'))}\n  GlobalKnownHostsFile /dev/null\n  HostKeyAlias nr-${id}\n  ProxyCommand ${quote(process.execPath)} ${quote(helper)} ${quote(join(directory, 'access.sock'))}\n  ForwardAgent no\n  ClearAllForwardings yes\n  RequestTTY auto\n`,
  };
}
// Files and socket are reachable only by the S service OS account. Requests
// still check the authoritative state and tunnel generation before opening.
export class NativeSSH {
  private entries = new Map<string, Server>();
  private pending = new Map<string, Promise<unknown>>();
  readonly root: string;
  constructor(readonly hub: TunnelHub, root: string, readonly helper: string) {
    this.root = resolve(root);
    if (process.platform === 'win32') throw new Error('Native SSH proxy requires the Linux S container');
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    if (lstatSync(this.root).isSymbolicLink() || !lstatSync(this.root).isDirectory() || lstatSync(this.root).uid !== process.getuid!()) throw new Error('Unsafe runtime directory');
    chmodSync(this.root, 0o700);
    hub.service.on('cleanup', this.remove);
    // tmpfs may survive an app process crash; discard decrypted stale files.
    for (const id of hub.service.sessions.keys()) this.remove(id);
  }
  async get(id: string) {
    z.uuid().parse(id); this.hub.service.activeSummary(id);
    const pending = this.pending.get(id);
    if (pending) await pending;
    if (!this.entries.has(id)) {
      const creating = this.create(id); this.pending.set(id, creating);
      try { await creating; } finally { this.pending.delete(id); }
    }
    this.hub.service.activeSummary(id);
    return { configPath: join(this.root, id, 'config'), host: 'nr-' + id, scope: 'S container only' };
  }
  private async create(id: string) {
      const credentials = this.hub.service.credentials(id), directory = join(this.root, id);
      mkdirSync(directory, { mode: 0o700 });
      try {
        const files = sshFiles(id, credentials.device.account, credentials.device.hostKeys, directory, this.helper);
        durableWrite(join(directory, 'identity'), credentials.sshPrivate);
        durableWrite(join(directory, 'known_hosts'), files.known);
        durableWrite(join(directory, 'config'), files.config);
        const server = createServer(socket => {
          socket.on('error', () => {});
          try {
            const remote = this.hub.open(id);
            const close = () => { socket.destroy(); remote.destroy(); };
            remote.on('error', close); remote.on('close', close); socket.on('close', close);
            socket.pipe(remote).pipe(socket);
          } catch { socket.destroy(); }
        });
        this.entries.set(id, server);
        server.on('error', () => this.remove(id));
        await new Promise<void>((ok, fail) => { server.once('error', fail); server.listen(join(directory, 'access.sock'), () => { server.off('error', fail); ok(); }); });
        this.hub.service.activeSummary(id);
        chmodSync(join(directory, 'access.sock'), 0o600);
      } catch (error) { this.remove(id); throw error; }
  }
  private remove = (id: string) => {
    z.uuid().parse(id);
    this.entries.get(id)?.close(); this.entries.delete(id);
    const directory = join(this.root, id);
    if (existsSync(directory)) rmSync(directory, { recursive: true, force: true });
  };
  close() { this.hub.service.off('cleanup', this.remove); for (const id of [...this.entries.keys()]) this.remove(id); }
}
