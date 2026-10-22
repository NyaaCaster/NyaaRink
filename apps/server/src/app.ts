import express from 'express';
import { VERSION } from '@nyaarink/version';
import { randomUUID } from 'node:crypto';
import { routes, errorHandler, type RouteConfig } from './routes.js';
import type { RinkService } from './service.js';
export function createApp(service?: RinkService, config?: RouteConfig) {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => { res.locals.requestId = randomUUID(); res.setHeader('X-Request-Id', res.locals.requestId); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
  app.use(express.json({ limit: '32kb', strict: true }));
  app.get('/health/live', (_req, res) => { res.json({ status: 'ok', version: VERSION }); });
  // Until the authority and transport exist, this skeleton must never advertise readiness.
  app.get('/health/ready', (_req, res) => { res.status(503).json({ status: 'not_implemented', version: VERSION }); });
  app.get('/healthz', (_req, res) => { res.status(503).json({ status: service?.authority.frozen ? 'frozen' : 'not_implemented', version: VERSION }); });
  if (service && config) app.use(routes(service, config));
  app.use((_req, res) => { res.status(404).json({ error: { code: 'NOT_FOUND' } }); });
  app.use(errorHandler);
  return app;
}
