import express from 'express';
import { VERSION } from '@nyaarink/version';
import { randomUUID } from 'node:crypto';
import { routes, errorHandler, type RouteConfig } from './routes.js';
import type { RinkService } from './service.js';
import type { Artifacts } from './artifacts.js';
import type { NativeSSH } from './proxy.js';
import type { Operations } from './operations.js';
import type { Files } from './files.js';
import type { Shells } from './shells.js';
import { resolve } from 'node:path';
export function createApp(service?: RinkService, config?: RouteConfig, artifacts?: Artifacts, native?: NativeSSH, operations?: Operations, files?: Files, shells?: Shells) {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => { res.locals.requestId = randomUUID(); res.setHeader('X-Request-Id', res.locals.requestId); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
  app.use((_req, res, next) => { res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"); next(); });
  const json = express.json({ limit: '32kb', strict: true }), mcpJson = express.json({ limit: '1450kb', strict: true });
  app.use((req, res, next) => (req.path === '/mcp' ? mcpJson : json)(req, res, next));
  app.get('/health/live', (_req, res) => { res.json({ status: 'ok', version: VERSION }); });
  // Until the authority and transport exist, this skeleton must never advertise readiness.
  app.get('/health/ready', (_req, res) => { res.status(503).json({ status: 'not_implemented', version: VERSION }); });
  app.get('/healthz', (_req, res) => { res.status(503).json({ status: service?.authority.frozen ? 'frozen' : 'not_implemented', version: VERSION }); });
  if (service && config) app.use(routes(service, config, artifacts, native, operations, files, shells));
  const web = resolve('dist/web');
  app.use('/assets', express.static(resolve(web, 'assets'), { fallthrough: false, dotfiles: 'deny' }));
  app.get(/^\/(?:[A-Za-z0-9_-]{43})?$/, (_req, res) => { res.sendFile(resolve(web, 'index.html')); });
  app.use((_req, res) => { res.status(404).json({ error: { code: 'NOT_FOUND' } }); });
  app.use(errorHandler);
  return app;
}
