import type { Duplex } from 'node:stream';
import ssh2 from 'ssh2';
import type { Client } from 'ssh2';
import type { RinkService } from './service.js';

export async function authenticated(service: RinkService, id: string, socket: Duplex) {
  const credentials = service.credentials(id), client = new ssh2.Client();
  return new Promise<Client>((ok, fail) => {
    const failure = (error: Error) => { client.destroy(); socket.destroy(); fail(error); };
    client.on('error', failure);
    socket.on('error', failure);
    client.once('ready', () => { try { service.activeSummary(id); ok(client); } catch (error) { failure(error as Error); } });
    client.connect({ sock: socket, username: credentials.device.account, privateKey: credentials.sshPrivate,
      hostVerifier: (key: Buffer) => credentials.device.hostKeys.includes(key.toString('base64')), readyTimeout: 15000,
      keepaliveInterval: 15000, keepaliveCountMax: 3 });
  });
}
export async function checkCapabilities(client: Client, home: string) {
  let timer: NodeJS.Timeout | undefined;
  const checks = async () => {
    await new Promise<void>((ok, fail) => client.exec('echo NyaaRink', (error, stream) => {
      if (error) { fail(error); return; }
      let output = '', bytes = 0;
      stream.on('data', (data: Buffer) => { bytes += data.length; if (bytes > 4096) { stream.destroy(); fail(new Error('Probe output exceeded')); } else output += data.toString(); });
      stream.stderr.resume(); stream.on('error', fail);
      stream.on('close', (code: number) => code === 0 && output.includes('NyaaRink') ? ok() : fail(new Error('SSH exec unavailable')));
    }));
    await new Promise<void>((ok, fail) => client.shell({ term: 'xterm', cols: 80, rows: 24 }, (error, stream) => {
      if (error) { fail(error); return; } stream.on('error', () => {}); stream.resume(); stream.close(); ok();
    }));
    await new Promise<void>((ok, fail) => client.sftp((error, sftp) => {
      if (error) { fail(error); return; } sftp.on('error', fail);
      sftp.stat(home, error => { sftp.end(); error ? fail(error) : ok(); });
    }));
    await new Promise<void>((ok, fail) => client.forwardOut('127.0.0.1', 0, '127.0.0.1', 1, (error, stream) => {
      if (error && (error as Error & { reason?: number }).reason === 1) ok();
      else { stream?.destroy(); fail(new Error('SSH direct forwarding restriction unproven')); }
    }));
    await new Promise<void>((ok, fail) => client.forwardIn('127.0.0.1', 0, (error, port) => {
      if (error) ok(); else { client.unforwardIn('127.0.0.1', port, () => {}); fail(new Error('SSH remote forwarding must be denied')); }
    }));
  };
  try {
    await Promise.race([checks(), new Promise<never>((_, fail) => { timer = setTimeout(() => fail(new Error('SSH capability probe timed out')), 15000); })]);
  } finally { if (timer) clearTimeout(timer); client.destroy(); }
}
