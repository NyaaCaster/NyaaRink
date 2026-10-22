import { readFileSync, statSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { z } from 'zod';

const Environment = z.object({
  PUBLIC_BASE_URL: z.string().url(), PUBLIC_PORT: z.coerce.number().int().min(1024).max(65535).default(5116),
  MCP_API_KEY: z.string().min(32), MCP_API_KEY_PREVIOUS: z.string().default(''),
  API_KEY_PREVIOUS_UNTIL: z.string().default(''), TLS_CERT_DIR: z.string().min(1),
  STATE_DIR: z.string().min(1), AUTHORITY_DIR: z.string().min(1),
  SESSION_MASTER_KEY_FILE: z.string().min(1), CLIENT_ARTIFACT_DIR: z.string().min(1),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  RUNTIME_DIR: z.string().default('/run/nyaarink'),
});
export type Config = z.infer<typeof Environment> & { masterKey: Buffer };
export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const parsed = Environment.safeParse(env);
  if (!parsed.success) throw new Error('Invalid environment: ' + [...new Set(parsed.error.issues.map(i => i.path[0]))].join(', '));
  const config = parsed.data;
  const url = new URL(config.PUBLIC_BASE_URL);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || Number(url.port || 443) !== config.PUBLIC_PORT) throw new Error('PUBLIC_BASE_URL requires matching HTTPS origin');
  if (config.MCP_API_KEY_PREVIOUS) {
    const until = Date.parse(config.API_KEY_PREVIOUS_UNTIL);
    if (config.MCP_API_KEY_PREVIOUS.length < 32 || !Number.isFinite(until) || until > Date.now() + 24 * 3600_000) throw new Error('Invalid previous API key rotation window');
  }
  for (const field of ['TLS_CERT_DIR', 'STATE_DIR', 'AUTHORITY_DIR', 'CLIENT_ARTIFACT_DIR'] as const) {
    config[field] = realpathSync(config[field]);
    if (!statSync(config[field]).isDirectory()) throw new Error('Required directory unavailable: ' + field);
  }
  const state = resolve(config.STATE_DIR), authority = resolve(config.AUTHORITY_DIR);
  if (state === authority || state.startsWith(authority + '/') || authority.startsWith(state + '/') || state.startsWith(authority + '\\') || authority.startsWith(state + '\\')) throw new Error('State and authority must be independent directories');
  const certificate = new X509Certificate(readFileSync(join(config.TLS_CERT_DIR, 'fullchain.pem')));
  if (!certificate.checkHost(url.hostname) || Date.parse(certificate.validTo) <= Date.now() || Date.parse(certificate.validFrom) > Date.now()) throw new Error('TLS certificate does not match configured origin or validity');
  const masterKey = readFileSync(config.SESSION_MASTER_KEY_FILE);
  if (masterKey.length !== 32) throw new Error('Master key must contain exactly 32 bytes');
  return { ...config, masterKey };
}
