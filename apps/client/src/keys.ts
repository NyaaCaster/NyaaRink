import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, openSync, closeSync, fsyncSync, writeFileSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';
import { utils } from 'ssh2';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { syncDirectory } from '../../server/src/crypto.js';
import { privatePath } from './state.js';
import { windowsEnvironment } from './windows.js';

export function keyLine(sessionId: string, publicKey: string) {
  if (!/^[0-9a-f-]{36}$/.test(sessionId)) throw new Error('Invalid session');
  const parts = publicKey.trim().split(/\s+/);
  if (parts[0] !== 'ssh-ed25519' || !parts[1] || parts[1].length > 512 || !/^[A-Za-z0-9+/]+=*$/.test(parts[1])) throw new Error('Invalid SSH public key');
  const parsed = utils.parseKey(`${parts[0]} ${parts[1]}`);
  if (parsed instanceof Error || Array.isArray(parsed) || parsed.type !== 'ssh-ed25519') throw new Error('Invalid SSH key');
  return `from="127.0.0.1,::1",restrict,pty ssh-ed25519 ${parts[1]} nyaarink:${sessionId}`;
}
export function changeKey(path: string, sessionId: string, publicKey: string, add: boolean) {
  const dir = dirname(path); mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (lstatSync(dir).isSymbolicLink() || (existsSync(path) && (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile() || lstatSync(path).nlink !== 1))) throw new Error('Unsafe authorized_keys path');
  if (process.platform !== 'win32' && (lstatSync(dir).uid !== process.getuid!() || (lstatSync(dir).mode & 0o077))) throw new Error('Unsafe SSH directory ownership or mode');
  const lock = path + '.nyaarink.lock', fd = openSync(lock, 'wx', 0o600);
  const temp = path + '.' + randomUUID() + '.tmp', existed = existsSync(path);
  let backup: string | undefined;
  try {
    const original = existed ? readFileSync(path, 'utf8') : '', line = keyLine(sessionId, publicKey);
    if (Buffer.byteLength(original) > 4 * 1024 * 1024) throw new Error('authorized_keys too large');
    const lines = original.split(/\r?\n/), marker = `nyaarink:${sessionId}`;
    if (add && lines.some(item => item.includes(marker) && item !== line)) throw new Error('Conflicting session key marker');
    if (add && lines.includes(line)) return;
    if (!add && !lines.includes(line)) return;
    const result = add ? original + (original && !original.endsWith('\n') ? '\n' : '') + line + '\n' : original.split(/(?<=\n)/).filter(item => item.replace(/\r?\n$/, '') !== line).join('');
    if (existed) {
      backup = path + '.nyaarink-backup-' + randomUUID();
      const backupFd = openSync(backup, 'wx', 0o600); closeSync(backupFd);
      privatePath(backup);
      const backupWrite = openSync(backup, 'w');
      try { writeFileSync(backupWrite, original); fsyncSync(backupWrite); } finally { closeSync(backupWrite); }
    }
    const out = openSync(temp, 'wx', 0o600);
    try { writeFileSync(out, result); fsyncSync(out); } finally { closeSync(out); }
    if (process.platform === 'win32') {
      // Copy the existing DACL to the replacement before the atomic rename.
      if (existed) {
        const script = '$ErrorActionPreference="Stop"; $section=[Security.AccessControl.AccessControlSections]::Access;' +
          '$source=[IO.File]::GetAccessControl($env:NR_OLD,$section); $acl=[Security.AccessControl.FileSecurity]::new();' +
          '$acl.SetSecurityDescriptorSddlForm($source.GetSecurityDescriptorSddlForm($section),$section);' +
          '[IO.File]::SetAccessControl($env:NR_NEW,$acl)';
        execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { env: windowsEnvironment({ ...process.env, NR_NEW: temp, NR_OLD: path }), stdio: 'pipe', windowsHide: true });
      } else if (/administrators_authorized_keys/i.test(path)) {
        execFileSync('icacls.exe', [temp, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F'], { stdio: 'pipe', windowsHide: true });
      } else { privatePath(dir, true); privatePath(temp); }
    } else {
      if (existed && (lstatSync(path).uid !== process.getuid!() || (lstatSync(path).mode & 0o077))) throw new Error('Unsafe authorized_keys ownership or mode');
      chmodSync(temp, existed ? lstatSync(path).mode & 0o777 : 0o600);
    }
    renameSync(temp, path); syncDirectory(dir);
    if (backup) rmSync(backup); // Successful replacement; a failure retains the backup for recovery.
  } finally { closeSync(fd); rmSync(lock, { force: true }); rmSync(temp, { force: true }); }
}
