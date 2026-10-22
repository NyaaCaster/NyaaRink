import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { RELEASE_PUBLIC_KEY } from './release-key.js';
export const Manifest = z.object({ v: z.literal(1), version: z.string().regex(/^\d+\.\d+\.\d+$/), platform: z.enum(['win32', 'linux']), arch: z.literal('x64'),
  nodeVersion: z.string().regex(/^24\.\d+\.\d+$/), minimumSystem: z.string(),
  files: z.record(z.string().regex(/^[A-Za-z0-9_.-]+$/), z.string().regex(/^[a-f0-9]{64}$/)),
}).strict();
export function verifyRelease(directory: string, expectedVersion: string, platform: string = process.platform, publicKey = RELEASE_PUBLIC_KEY) {
  const text = readFileSync(join(directory, 'manifest.json'));
  if (text.length > 32768) throw new Error('Release manifest too large');
  const key = createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, text, key, readFileSync(join(directory, 'manifest.sig')))) throw new Error('Release signature invalid');
  const manifest = Manifest.parse(JSON.parse(text.toString()));
  if (manifest.version !== expectedVersion || manifest.platform !== platform || manifest.arch !== process.arch) throw new Error('Release version or platform mismatch');
  for (const file of ['client.cjs', 'verify.cjs', platform === 'win32' ? 'node.exe' : 'node', 'NODE-LICENSE', 'LICENSE', 'THIRD-PARTY-NOTICES']) if (!manifest.files[file]) throw new Error('Incomplete release');
  for (const [file, digest] of Object.entries(manifest.files)) {
    const path = join(directory, file), stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || createHash('sha256').update(readFileSync(path)).digest('hex') !== digest) throw new Error(`Release file rejected: ${file}`);
  }
  const allowed = new Set([...Object.keys(manifest.files), 'manifest.json', 'manifest.sig']);
  if (readdirSync(directory).some(file => !allowed.has(file))) throw new Error('Unexpected release file');
  if (manifest.nodeVersion !== process.versions.node) throw new Error('Portable Node runtime version mismatch');
  return manifest;
}
