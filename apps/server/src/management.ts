import type { IncomingMessage } from 'node:http';
import { equal, hash } from './crypto.js';
import type { Config } from './config.js';
export function authorized(req: IncomingMessage, config: Pick<Config, 'MCP_API_KEY' | 'MCP_API_KEY_PREVIOUS' | 'API_KEY_PREVIOUS_UNTIL'>) {
  const header = req.headers.authorization ?? '', key = header.startsWith('Bearer ') ? header.slice(7) : '';
  return equal(hash(key), hash(config.MCP_API_KEY)) || (!!config.MCP_API_KEY_PREVIOUS && Date.parse(config.API_KEY_PREVIOUS_UNTIL) > Date.now() && equal(hash(key), hash(config.MCP_API_KEY_PREVIOUS)));
}
