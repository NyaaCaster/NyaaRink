import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual, sign, verify, createPublicKey } from 'node:crypto';
import { openSync, closeSync, writeFileSync, fsyncSync, renameSync, mkdirSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';

export const token = () => randomBytes(32).toString('base64url');
export const hash = (input: string | Buffer) => createHash('sha256').update(input).digest('hex');
export const mac = (key: Buffer, input: string) => createHmac('sha256', key).update(input).digest('hex');
export function equal(a: string, b: string) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
export function seal(key: Buffer, data: unknown, aad: string) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  return JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: ciphertext.toString('base64') });
}
export function unseal<T>(key: Buffer, text: string, aad: string): T {
  const data = JSON.parse(text);
  if (data.v !== 1) throw new Error('Unsupported encrypted object');
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'base64'));
  cipher.setAAD(Buffer.from(aad)); cipher.setAuthTag(Buffer.from(data.tag, 'base64'));
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(data.data, 'base64')), cipher.final()]).toString());
}
export function syncDirectory(path: string) {
  if (process.platform === 'win32') return; // Windows rename is atomic; directory fsync is unavailable.
  const fd = openSync(path, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); }
}
export function durableWrite(path: string, text: string | Buffer) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = path + '.' + token() + '.tmp';
  const fd = openSync(temp, 'wx', 0o600);
  try {
    try { writeFileSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path); syncDirectory(dirname(path));
  } finally { rmSync(temp, { force: true }); }
}
export function deviceMessage(operation: string, instanceId: string, epoch: string, sessionId: string, nonce: string, body: unknown) {
  return JSON.stringify([1, operation, instanceId, epoch, sessionId, nonce, body]);
}
export function deviceVerify(publicKey: string, message: string, signature: string) {
  try {
    const key = createPublicKey(publicKey);
    return key.asymmetricKeyType === 'ed25519' && verify(null, Buffer.from(message), key, Buffer.from(signature, 'base64url'));
  } catch { return false; }
}
export const deviceSign = (privateKey: string, message: string) => sign(null, Buffer.from(message), privateKey).toString('base64url');
