import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, truncateSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { durableWrite, equal, hash, mac, seal, unseal, syncDirectory } from './crypto.js';
import { z } from 'zod';
import { DomainError } from '@nyaarink/contracts';

export type AuthorityEvent = { seq: number; instanceId: string; epoch: string; schemaVersion: 1; eventId: string; time: string; previous: string; type: string; payload: Record<string, unknown> };
type Frame = { event: AuthorityEvent; hmac: string };
type Identity = { instanceId: string; epoch: string; v: 1 };
type Head = { seq: number; hash: string; instanceId: string; epoch: string; hmac: string };
export class Authority extends EventEmitter {
  identity!: Identity;
  events: AuthorityEvent[] = [];
  frozen = true;
  freezeReason = 'UNINITIALIZED';
  private previous = '0'.repeat(64);
  private fd?: number;
  private lockOwned = false;
  private lockPath: string;
  constructor(readonly directory: string, private key: Buffer, readonly fault?: (point: string) => void, readonly readOnly = false) {
    super(); this.lockPath = join(directory, 'writer.lock');
    try { this.load(); } catch { this.freeze('AUTHORITY_INTEGRITY'); }
  }
  static initialize(directory: string, key: Buffer) {
    if (key.length !== 32) throw new Error('Invalid master key length');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (readdirSync(directory).length) throw new Error('Refuse to replace authority');
    const identity: Identity = { instanceId: randomUUID(), epoch: randomUUID(), v: 1 };
    durableWrite(join(directory, 'identity.json'), JSON.stringify({ identity, hmac: mac(key, JSON.stringify(identity)) }));
    durableWrite(join(directory, 'events.bin'), Buffer.alloc(0));
    const head = { seq: 0, hash: '0'.repeat(64), instanceId: identity.instanceId, epoch: identity.epoch };
    durableWrite(join(directory, 'head.json'), JSON.stringify({ ...head, hmac: mac(key, JSON.stringify(head)) }));
    mkdirSync(join(directory, 'vault'), { mode: 0o700 });
  }
  private acquire() {
    try { this.fd = openSync(this.lockPath, 'wx', 0o600); }
    catch {
      const pid = Number(readFileSync(this.lockPath, 'utf8'));
      if (!Number.isSafeInteger(pid) || pid < 1) throw new Error('Invalid authority lock');
      try { process.kill(pid, 0); throw new Error('Authority already has a writer'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      rmSync(this.lockPath); this.fd = openSync(this.lockPath, 'wx', 0o600);
    }
    this.lockOwned = true; writeSync(this.fd!, String(process.pid)); fsyncSync(this.fd!);
  }
  private load() {
    if (!existsSync(join(this.directory, 'identity.json'))) return;
    if (!this.readOnly) this.acquire();
    const encoded = JSON.parse(readFileSync(join(this.directory, 'identity.json'), 'utf8'));
    if (!equal(encoded.hmac, mac(this.key, JSON.stringify(encoded.identity)))) throw new Error('Identity authentication failed');
    this.identity = z.object({ instanceId: z.string().uuid(), epoch: z.string().uuid(), v: z.literal(1) }).strict().parse(encoded.identity);
    const head: Head = JSON.parse(readFileSync(join(this.directory, 'head.json'), 'utf8'));
    const { hmac, ...body } = head;
    z.object({ seq: z.number().int().nonnegative(), hash: z.string().regex(/^[a-f0-9]{64}$/), instanceId: z.string().uuid(), epoch: z.string().uuid(), hmac: z.string() }).strict().parse(head);
    if (!equal(hmac, mac(this.key, JSON.stringify(body))) || head.instanceId !== this.identity.instanceId || head.epoch !== this.identity.epoch) throw new Error('Invalid head');
    const data = readFileSync(join(this.directory, 'events.bin'));
    let offset = 0, verifiedHead = head.seq === 0 && head.hash === this.previous;
    while (offset < data.length) {
      if (offset + 4 > data.length) break;
      const length = data.readUInt32BE(offset);
      if (length < 1 || length > 2 * 1024 * 1024) throw new Error('Invalid frame length');
      if (offset + 4 + length > data.length) break;
      const frame: Frame = JSON.parse(data.subarray(offset + 4, offset + 4 + length).toString());
      const event = frame.event;
      z.object({ seq: z.number().int().positive(), instanceId: z.string().uuid(), epoch: z.string().uuid(), schemaVersion: z.literal(1), eventId: z.string().uuid(), time: z.iso.datetime(), previous: z.string(), type: z.string(), payload: z.record(z.string(), z.unknown()) }).strict().parse(event);
      if (!equal(frame.hmac, mac(this.key, JSON.stringify(event))) || event.schemaVersion !== 1 || event.seq !== this.events.length + 1 || event.previous !== this.previous || event.instanceId !== this.identity.instanceId || event.epoch !== this.identity.epoch) throw new Error('Invalid event chain');
      this.previous = hash(JSON.stringify(frame)); this.events.push(event);
      if (head.seq === event.seq) verifiedHead = head.hash === this.previous;
      offset += 4 + length;
    }
    if (!verifiedHead || head.seq > this.events.length) throw new Error('Head ahead or inconsistent');
    if (offset !== data.length && !this.readOnly) {
      truncateSync(join(this.directory, 'events.bin'), offset);
      const ledger = openSync(join(this.directory, 'events.bin'), 'r+');
      try { fsyncSync(ledger); } finally { closeSync(ledger); }
    }
    if (!this.readOnly) this.writeHead();
    this.frozen = false; this.freezeReason = '';
  }
  private writeHead() {
    const body = { seq: this.events.length, hash: this.previous, instanceId: this.identity.instanceId, epoch: this.identity.epoch };
    durableWrite(join(this.directory, 'head.json'), JSON.stringify({ ...body, hmac: mac(this.key, JSON.stringify(body)) }));
  }
  assertAvailable() { if (this.frozen) throw new DomainError('FROZEN', 503); }
  freeze(reason: string) { this.frozen = true; this.freezeReason = reason; this.emit('frozen'); }
  append(type: string, payload: Record<string, unknown>) {
    if (this.readOnly) throw new Error('Read-only authority');
    this.assertAvailable();
    const event: AuthorityEvent = { seq: this.events.length + 1, instanceId: this.identity.instanceId, epoch: this.identity.epoch, schemaVersion: 1, eventId: randomUUID(), time: new Date().toISOString(), previous: this.previous, type, payload };
    const frame: Frame = { event, hmac: mac(this.key, JSON.stringify(event)) };
    const encoded = Buffer.from(JSON.stringify(frame)), size = Buffer.alloc(4); size.writeUInt32BE(encoded.length);
    if (encoded.length > 2 * 1024 * 1024) throw new DomainError('LIMIT_EXCEEDED', 413);
    let fd: number | undefined;
    try {
      this.fault?.('before_append');
      fd = openSync(join(this.directory, 'events.bin'), 'a', 0o600);
      const data = Buffer.concat([size, encoded]);
      let offset = 0; while (offset < data.length) { const written = writeSync(fd, data, offset); if (!written) throw new Error('Short write'); offset += written; }
      fsyncSync(fd); closeSync(fd); fd = undefined;
      this.events.push(event); this.previous = hash(JSON.stringify(frame));
      this.fault?.('after_fsync'); this.writeHead();
      this.emit('event', event); return event;
    } catch {
      if (fd !== undefined) closeSync(fd);
      this.freeze('AUTHORITY_WRITE_FAILED'); throw new DomainError('FROZEN', 503);
    }
  }
  private aad(id: string) { z.string().uuid().parse(id); return JSON.stringify([this.identity.instanceId, this.identity.epoch, id, 'session', 1]); }
  saveSecret(id: string, value: unknown) {
    if (this.readOnly) throw new Error('Read-only authority');
    this.assertAvailable();
    try { durableWrite(join(this.directory, 'vault', id + '.json'), seal(this.key, value, this.aad(id))); }
    catch { this.freeze('VAULT_WRITE_FAILED'); throw new DomainError('FROZEN', 503); }
  }
  secret<T>(id: string): T {
    this.assertAvailable();
    try { return unseal<T>(this.key, readFileSync(join(this.directory, 'vault', id + '.json'), 'utf8'), this.aad(id)); }
    catch { this.freeze('VAULT_INTEGRITY'); throw new DomainError('FROZEN', 503); }
  }
  deleteSecret(id: string) { if (this.readOnly) throw new Error('Read-only authority'); this.aad(id); rmSync(join(this.directory, 'vault', id + '.json'), { force: true }); syncDirectory(join(this.directory, 'vault')); }
  close() {
    if (this.fd !== undefined) closeSync(this.fd);
    if (this.lockOwned) rmSync(this.lockPath, { force: true });
    this.fd = undefined; this.lockOwned = false;
  }
}
