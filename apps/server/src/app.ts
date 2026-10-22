import express from 'express';
import { VERSION } from '@nyaarink/version';
export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
  app.get('/health/live', (_req, res) => { res.json({ status: 'ok', version: VERSION }); });
  // Until the authority and transport exist, this skeleton must never advertise readiness.
  app.get('/health/ready', (_req, res) => { res.status(503).json({ status: 'not_implemented', version: VERSION }); });
  app.use((_req, res) => { res.status(404).json({ error: { code: 'NOT_FOUND' } }); });
  return app;
}
