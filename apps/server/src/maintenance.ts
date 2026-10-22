import { readFileSync, cpSync, mkdirSync, readdirSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { Authority } from './authority.js';
import { RinkService, Payloads } from './service.js';
import { durableWrite, hash } from './crypto.js';
import { randomUUID } from 'node:crypto';

// Offline operations acquire the same writer lock. They never stop a running service.
export async function maintain(operation: string, argument: string | undefined, env: NodeJS.ProcessEnv) {
  const directory = resolve(env.AUTHORITY_DIR ?? ''), state = resolve(env.STATE_DIR ?? ''), key = readFileSync(env.SESSION_MASTER_KEY_FILE ?? '');
  if (!env.AUTHORITY_DIR || !env.STATE_DIR || key.length !== 32) throw new Error('Missing private configuration');
  const a = new Authority(directory, key, undefined, operation === 'verify-authority');
  try {
    a.assertAvailable();
    if (operation === 'verify-authority') {
      const references = new Map<string, string[]>(), active = new Set<string>();
      for (const event of a.events) {
        if (!Object.hasOwn(Payloads, event.type)) throw new Error('Unsupported event');
        const p = event.payload;
        Payloads[event.type as keyof typeof Payloads].parse(p);
        if (event.type === 'accept') active.add(String(p.id));
        if (event.type === 'bootstrap') references.set(String(p.id), [String(p.secretId)]);
        if (event.type === 'enroll') { const id = (p.data as { sessionId: string }).sessionId; references.set(id, [id]); }
        if (event.type === 'revoke') { active.delete(String(p.id)); references.delete(String(p.id)); }
      }
      for (const id of active) for (const reference of references.get(id) ?? []) a.secret(reference);
      return { verified: true, seq: a.events.length };
    }
    if (operation === 'backup-authority') {
      const target = join(state, 'backups', 'authority-' + randomUUID()); mkdirSync(target, { recursive: true, mode: 0o700 });
      for (const name of ['identity.json', 'head.json', 'events.bin', 'vault']) cpSync(join(directory, name), join(target, name), { recursive: true, errorOnExist: true, force: false });
      const files: Record<string, string> = {};
      for (const name of ['identity.json', 'head.json', 'events.bin', ...readdirSync(join(target, 'vault')).map(n => 'vault/' + n)]) {
        files[name] = hash(readFileSync(join(target, name))); chmodSync(join(target, name), 0o600);
      }
      durableWrite(join(target, 'manifest.json'), JSON.stringify({ schema: 1, ...a.identity, seq: a.events.length, files }));
      return { backup: target, seq: a.events.length };
    }
    if (operation === 'restore-database') {
      if (!argument) throw new Error('Missing database');
      const source = new Database(resolve(argument), { readonly: true, fileMustExist: true });
      try {
        const row = source.prepare('SELECT instanceId, epoch, seq FROM snapshot WHERE id=1').get() as { instanceId: string; epoch: string; seq: number } | undefined;
        if (!row || row.instanceId !== a.identity.instanceId || row.epoch !== a.identity.epoch || row.seq > a.events.length) throw new Error('Backup identity or head mismatch');
        const manifest = JSON.parse(readFileSync(resolve(argument) + '.manifest.json', 'utf8'));
        if (manifest.sha256 !== hash(readFileSync(resolve(argument))) || manifest.instanceId !== row.instanceId || manifest.epoch !== row.epoch) throw new Error('Backup checksum mismatch');
        // Latest authority is the complete source of truth. Validate the supplied old snapshot,
        // then rebuild current DB directly instead of copying an obsolete authorization image.
        const service = await RinkService.open(a, state, env.PUBLIC_BASE_URL ?? 'https://example.invalid:5116');
        await service.close(); return { restored: true, seq: a.events.length };
      } finally { source.close(); }
    }
    throw new Error('Unknown maintenance operation');
  } finally { a.close(); }
}
if (process.argv[1]?.endsWith('maintenance.js') || process.argv[1]?.endsWith('maintenance.ts')) {
  try { console.log(JSON.stringify(await maintain(process.argv[2] ?? '', process.argv[3], process.env))); }
  catch { console.error('NyaaRink maintenance refused: stop the service for offline operations and verify private data integrity.'); process.exitCode = 1; }
}
