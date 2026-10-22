import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, renameSync, rmSync, chmodSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { VERSION } from '@nyaarink/version';
import { verifyRelease } from './release.js';
import { privatePath, stateRoot } from './state.js';

export function installRuntime(source: string, root = stateRoot()) {
  source = resolve(source); verifyRelease(source, VERSION);
  mkdirSync(root, { recursive: true, mode: 0o700 }); privatePath(root, true);
  const directory = join(root, `runtime-${VERSION}-${process.platform}-${process.arch}`);
  if (existsSync(directory)) { privatePath(directory, true); verifyRelease(directory, VERSION); return directory; }
  const staging = join(root, `.runtime-${randomUUID()}`);
  mkdirSync(staging, { mode: 0o700 }); privatePath(staging, true);
  try {
    for (const file of readdirSync(source)) {
      if (!lstatSync(join(source, file)).isFile()) throw new Error('Invalid release entry');
      const destination = join(staging, file); copyFileSync(join(source, file), destination);
      if (process.platform !== 'win32') chmodSync(destination, file === 'node' ? 0o700 : 0o600);
      privatePath(destination);
    }
    verifyRelease(staging, VERSION);
    try { renameSync(staging, directory); } catch (error) { if (!existsSync(directory)) throw error; verifyRelease(directory, VERSION); }
    return directory;
  } finally { rmSync(staging, { recursive: true, force: true }); }
}
