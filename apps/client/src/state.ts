import { closeSync, existsSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync, fsyncSync, lstatSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { z } from 'zod';
import { Bootstrap, Enrollment } from '../../../packages/contracts/device.js';
import { durableWrite } from '../../server/src/crypto.js';
import { windowsEnvironment } from './windows.js';

export const LocalState = z.object({ v: z.literal(1), bootstrap: Bootstrap,
  devicePrivateKey: z.string().optional(), devicePublicKey: z.string(), enrollment: Enrollment.optional(),
  phase: z.enum(['preparing', 'enrolled', 'ready', 'revoked', 'cleaned']),
  sshPublicKey: z.string().optional(), authorizedKeys: z.string().optional(), loginFile: z.string().optional(),
  runtime: z.string(), cleanup: z.enum(['pending', 'confirmed', 'failed']).default('pending'),
  reported: z.boolean().default(false), releaseVersion: z.string(),
}).strict();
export type State = z.infer<typeof LocalState>;
export function stateRoot() {
  if (process.platform === 'win32') {
    if (!process.env.LOCALAPPDATA) throw new Error('LOCALAPPDATA unavailable; run as the target account');
    return join(process.env.LOCALAPPDATA, 'NyaaRink');
  }
  return join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share'), 'nyaarink');
}
export function privatePath(path: string, directory = false) {
  if (lstatSync(path).isSymbolicLink()) throw new Error('Private paths must not be symbolic links');
  if (process.platform === 'win32') {
    const identity = execFileSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
    const sid = identity.match(/S-1-5-[0-9-]+/)?.[0]; if (!sid) throw new Error('Cannot determine account SID');
    const script = '$ErrorActionPreference="Stop"; $acl=[System.Security.AccessControl.' + (directory ? 'DirectorySecurity' : 'FileSecurity') + ']::new();' +
      '$acl.SetSecurityDescriptorSddlForm($env:NR_SDDL); [System.IO.' + (directory ? 'Directory' : 'File') + ']::SetAccessControl($env:NR_PRIVATE_PATH,$acl)';
    const inherit = directory ? 'OICI' : '';
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      env: windowsEnvironment({ ...process.env, NR_PRIVATE_PATH: path, NR_SDDL: `O:${sid}D:P(A;${inherit};FA;;;${sid})(A;${inherit};FA;;;SY)` }), stdio: 'pipe', windowsHide: true,
    });
  } else {
    const stat = lstatSync(path);
    if (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0) throw new Error('Unsafe private path permissions');
  }
}
export class StateStore {
  readonly directory: string;
  readonly file: string;
  constructor(readonly sessionId: string, root = stateRoot()) {
    z.string().uuid().parse(sessionId);
    mkdirSync(root, { recursive: true, mode: 0o700 }); privatePath(root, true);
    this.directory = join(realpathSync(root), sessionId);
    mkdirSync(this.directory, { mode: 0o700, recursive: true }); privatePath(this.directory, true);
    this.file = join(this.directory, 'state.json');
  }
  read(): State { privatePath(this.file); const state = LocalState.parse(JSON.parse(readFileSync(this.file, 'utf8'))); if (state.bootstrap.sessionId !== this.sessionId) throw new Error('State identity mismatch'); if (this.revoked() && state.phase !== 'cleaned') state.phase = 'revoked'; return state; }
  exists() { return existsSync(this.file); }
  revoked() { return existsSync(join(this.directory, 'revoked')); }
  markRevoked() { durableWrite(join(this.directory, 'revoked'), JSON.stringify({ sessionId: this.sessionId, revoked: true })); }
  write(state: State) { LocalState.parse(state); if (state.bootstrap.sessionId !== this.sessionId || !isAbsolute(state.runtime)) throw new Error('State identity mismatch'); if (this.revoked() && !['revoked', 'cleaned'].includes(state.phase)) throw new Error('Local revocation is permanent'); durableWrite(this.file, JSON.stringify(state)); privatePath(this.file); }
  lock() {
    const path = join(this.directory, 'writer.lock');
    if (existsSync(path)) {
      const pid = Number(readFileSync(path, 'utf8')); if (!Number.isSafeInteger(pid) || pid < 1) throw new Error('Invalid client lock');
      try { process.kill(pid, 0); throw new Error('Client already running'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      unlinkSync(path);
    }
    const fd = openSync(path, 'wx', 0o600); writeFileSync(fd, String(process.pid)); fsyncSync(fd); closeSync(fd);
    return () => { if (existsSync(path) && readFileSync(path, 'utf8') === String(process.pid)) unlinkSync(path); };
  }
}
export function deviceKeys() {
  return generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
}
