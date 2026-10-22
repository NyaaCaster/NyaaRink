import Database from 'better-sqlite3';
import { mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Authority } from './authority.js';
import { durableWrite, hash } from './crypto.js';
import { readFileSync } from 'node:fs';

// This database is a disposable projection. No authorization decision reads it.
export class Projection {
  readonly db: Database.Database;
  private constructor(readonly directory: string) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    this.db = new Database(join(directory, 'state.db'));
    chmodSync(join(directory, 'state.db'), 0o600);
  }
  static async open(directory: string, authority: Authority) {
    authority.assertAvailable();
    const projection = new Projection(directory);
    try {
      await projection.backup(authority);
      const table = projection.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshot'").get();
      if (table) {
        const previous = projection.db.prepare('SELECT instanceId, epoch, seq FROM snapshot WHERE id=1').get() as { instanceId: string; epoch: string; seq: number } | undefined;
        if (previous && (previous.instanceId !== authority.identity.instanceId || previous.epoch !== authority.identity.epoch || previous.seq > authority.events.length)) throw new Error('Projection ahead or wrong instance');
      }
      projection.db.pragma('journal_mode = WAL'); projection.db.pragma('synchronous = FULL');
      projection.db.exec('CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), instanceId TEXT NOT NULL, epoch TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL)');
      return projection;
    } catch (error) { projection.close(); authority.freeze('PROJECTION_INTEGRITY'); throw error; }
  }
  async backup(authority: Authority, destination?: string) {
    const directory = join(this.directory, 'backups'); mkdirSync(directory, { recursive: true, mode: 0o700 });
    const path = destination ?? join(directory, `${Date.now()}-${randomUUID()}.db`);
    await this.db.backup(path); chmodSync(path, 0o600);
    const row = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshot'").get();
    const snapshot = row ? this.db.prepare('SELECT instanceId, epoch, seq FROM snapshot WHERE id=1').get() as { instanceId: string; epoch: string; seq: number } | undefined : undefined;
    durableWrite(path + '.manifest.json', JSON.stringify({ schema: 1, ...authority.identity, seq: snapshot?.seq ?? 0, authorityHeadSeq: authority.events.length, sha256: hash(readFileSync(path)) }));
    return path;
  }
  // Caller must first await backup while holding the service mutation queue.
  write(authority: Authority, state: unknown) {
    authority.assertAvailable();
    this.db.prepare('INSERT INTO snapshot VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET instanceId=excluded.instanceId, epoch=excluded.epoch, seq=excluded.seq, body=excluded.body')
      .run(authority.identity.instanceId, authority.identity.epoch, authority.events.length, JSON.stringify(state));
  }
  close() { this.db.close(); }
}
