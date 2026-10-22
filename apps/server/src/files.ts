import { randomUUID } from 'node:crypto';
import { posix } from 'node:path';
import { Transform, type Readable, type Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { SFTPWrapper, Stats } from 'ssh2';
import { DomainError, DEFAULTS } from '@nyaarink/contracts';
import type { TunnelHub } from './tunnel.js';

export function filePath(root: string, requested: string) {
  if (!requested || requested.length > 4096 || /[\0\r\n\\]/.test(requested) || requested.split('/').includes('..')) throw new DomainError('INVALID_REQUEST', 400);
  root = root.replace(/\/$/, '');
  if (!root || !root.startsWith('/')) throw new DomainError('INVALID_REQUEST', 400);
  const target = posix.normalize(requested.startsWith('/') ? requested : root + '/' + requested);
  if (!target.startsWith(root + '/') || target === root || /:/.test(target.slice(root.length))) throw new DomainError('INVALID_REQUEST', 400);
  return target;
}
const realpath = (sftp: SFTPWrapper, path: string) => new Promise<string>((ok, fail) => sftp.realpath(path, (error, result) => error ? fail(error) : ok(result)));
const stat = (sftp: SFTPWrapper, path: string) => new Promise<Stats>((ok, fail) => sftp.lstat(path, (error, result) => error ? fail(error) : ok(result)));
const unlink = (sftp: SFTPWrapper, path: string) => new Promise<void>(ok => sftp.unlink(path, () => ok()));
async function checked(sftp: SFTPWrapper, home: string, path: string, upload: boolean) {
  // Pin the home resolved by the actual SFTP server, not a shell command.
  const root = (await realpath(sftp, home.replaceAll('\\', '/'))).replace(/\/$/, ''), target = filePath(root, path);
  const parts = target.slice(root.length + 1).split('/'); let current = root;
  const homeStat = await stat(sftp, root); if (!homeStat.isDirectory() || homeStat.isSymbolicLink()) throw new DomainError('INVALID_REQUEST', 400);
  for (let n = 0; n < parts.length; n++) {
    current += '/' + parts[n];
    let info: Stats;
    try { info = await stat(sftp, current); } catch (error) {
      if (upload && n === parts.length - 1 && (error as { code?: number }).code === 2) return target;
      throw error;
    }
    if (info.isSymbolicLink() || (n < parts.length - 1 ? !info.isDirectory() : !info.isFile())) throw new DomainError('INVALID_REQUEST', 400);
  }
  return target;
}
export class Files {
  constructor(readonly hub: TunnelHub) {}
  async transfer(id: string, path: string, mode: 'upload' | 'download', stream: Readable | Writable, limit = DEFAULTS.maxFileBytes) {
    const { device } = this.hub.service.credentials(id), client = await this.hub.connect(id);
    let sftp: SFTPWrapper | undefined, temporary: string | undefined;
    // Close may precede SFTP setup and pipeline's error listeners.
    const streamError = () => {};
    stream.on('error', streamError);
    const closed = () => stream.destroy(new Error('SSH transport closed'));
    client.once('close', closed);
    try {
      sftp = await new Promise<SFTPWrapper>((ok, fail) => client.sftp((error, result) => error ? fail(error) : ok(result)));
      // A remote error is handled by the streams/promises and never logged.
      sftp.on('error', () => {});
      const target = await checked(sftp, device.home, path, mode === 'upload'); this.hub.operation(id);
      if (mode === 'download' && (await stat(sftp, target)).size > limit) throw new DomainError('LIMIT_EXCEEDED', 413);
      let bytes = 0;
      const counter = new Transform({ transform(chunk: Buffer, _encoding, done) { bytes += chunk.length; done(bytes > limit ? new DomainError('LIMIT_EXCEEDED', 413) : null, chunk); } });
      if (mode === 'upload') {
        temporary = posix.dirname(target) + '/.nyaarink-' + randomUUID();
        await pipeline(stream as Readable, counter, sftp.createWriteStream(temporary, { flags: 'wx', mode: 0o600 }));
        this.hub.service.activeSummary(id);
        await checked(sftp, device.home, path, true);
        const remote = sftp;
        // OpenSSH extension atomically replaces a regular destination. No
        // unlink-then-rename fallback which could destroy an existing file.
        await new Promise<void>((ok, fail) => remote.ext_openssh_rename(temporary!, target, error => error ? fail(error) : ok())); temporary = undefined;
      } else await pipeline(sftp.createReadStream(target), counter, stream as Writable);
      return { bytes };
    } finally {
      client.off('close', closed);
      if (temporary && sftp) {
        let timer: NodeJS.Timeout | undefined;
        try { await Promise.race([unlink(sftp, temporary), new Promise<void>(ok => { timer = setTimeout(ok, 1000); timer.unref(); })]); }
        finally { clearTimeout(timer); }
      }
      sftp?.end(); client.destroy();
      // destroy(error) may emit on the next tick after this finally returns.
      // Retain the harmless listener until close instead of exposing an
      // unhandled error between setup failure and asynchronous destruction.
      if (stream.closed) stream.off('error', streamError);
      else stream.once('close', () => stream.off('error', streamError));
    }
  }
}
