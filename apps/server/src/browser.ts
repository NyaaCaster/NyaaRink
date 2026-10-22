import type { IncomingMessage } from 'node:http';
import { equal, hash, mac } from './crypto.js';
import { DomainError } from '@nyaarink/contracts';
export const browserKey = (master: Buffer) => Buffer.from(mac(master, 'browser-cookie-v1'), 'hex');
export function browserCredential(req: IncomingMessage, key: Buffer) {
  const cookies = (req.headers.cookie ?? '').split(';').map(c => c.trim()).filter(c => c.startsWith('__Host-nr='));
  const value = cookies.length === 1 ? cookies[0]!.slice('__Host-nr='.length) : '', parts = value.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(parts[0]!) || !equal(parts[1]!, mac(key, parts[0]!))) throw new DomainError('UNAUTHORIZED', 401);
  return value;
}
export const browserHash = (req: IncomingMessage, key: Buffer) => hash(browserCredential(req, key));
