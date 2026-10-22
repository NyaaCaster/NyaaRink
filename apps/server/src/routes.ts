import { Router, type Request, type Response, type NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { DomainError } from '@nyaarink/contracts';
import { RinkService } from './service.js';
import { equal, hash, mac, token } from './crypto.js';
import type { Config } from './config.js';
import { Artifacts, connectionScript } from './artifacts.js';
import { join } from 'node:path';
import type { NativeSSH } from './proxy.js';
import type { Operations } from './operations.js';
import type { Files } from './files.js';
import { makeMcp } from './mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { authorized } from './management.js';
import type { Shells } from './shells.js';
import { browserCredential, browserKey } from './browser.js';

export type RouteConfig = Pick<Config, 'PUBLIC_BASE_URL' | 'MCP_API_KEY' | 'MCP_API_KEY_PREVIOUS' | 'API_KEY_PREVIOUS_UNTIL' | 'masterKey'>;
const Id = z.string().uuid();
const Credential = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const Signed = z.object({ sessionId: Id, nonce: Credential, signature: z.string().min(64).max(256) });
export function routes(service: RinkService, config: RouteConfig, artifacts?: Artifacts, native?: NativeSSH, operations?: Operations, files?: Files, shells?: Shells) {
  const router = Router(), buckets = new Map<string, { count: number; until: number }>();
  const origin = new URL(config.PUBLIC_BASE_URL).origin;
  const cookieKey = browserKey(config.masterKey);
  const requestKey = (req: Request) => Id.parse(req.get('Idempotency-Key'));
  const csrf = (value: string) => mac(cookieKey, 'csrf:' + hash(value));
  const browser = (req: Request, res: Response, establish = false) => {
    try { return browserCredential(req, cookieKey); } catch { /* Establish only on a safe read. */ }
    if (!establish) throw new DomainError('UNAUTHORIZED', 401);
    const raw = token(), next = raw + '.' + mac(cookieKey, raw);
    res.cookie('__Host-nr', next, { secure: true, httpOnly: true, sameSite: 'strict', path: '/', maxAge: 365 * 24 * 3600_000 }); return next;
  };
  const limit = (scope: string, maximum: number) => (req: Request, _res: Response, next: NextFunction) => {
    const now = Date.now(); for (const [key, b] of buckets) if (b.until <= now) buckets.delete(key);
    const key = scope + ':' + req.socket.remoteAddress;
    if (!buckets.has(key) && buckets.size >= 10000) throw new DomainError('LIMIT_EXCEEDED', 429);
    const b = buckets.get(key) ?? { count: 0, until: now + 60000 }; buckets.set(key, b);
    if (++b.count > maximum) throw new DomainError('LIMIT_EXCEEDED', 429); next();
  };
  router.use((req, _res, next) => {
    if (req.get('host') !== new URL(origin).host || (req.get('origin') && req.get('origin') !== origin)) throw new DomainError('UNAUTHORIZED', 403);
    next();
  });
  router.use(limit('all', 1000));
  if (artifacts) router.get('/downloads/:filename', (req, res) => {
    const item = artifacts.items.find(item => item.filename === req.params.filename);
    if (!item) throw new DomainError('NOT_FOUND', 404);
    res.sendFile(join(artifacts.directory, item.filename));
  });
  const manage = (req: Request, _res: Response, next: NextFunction) => {
    if (!authorized(req, config)) throw new DomainError('UNAUTHORIZED', 401); next();
  };
  const browserWrite = (req: Request, res: Response, next: NextFunction) => {
    const value = browser(req, res);
    if (req.get('origin') !== origin || !equal(req.get('X-NR-CSRF') ?? '', csrf(value))) throw new DomainError('UNAUTHORIZED', 403);
    res.locals.browserHash = hash(value); next();
  };
  router.post('/mcp', manage, async (req, res) => {
    const server = makeMcp(service, operations, native, files);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.once('close', () => { void transport.close(); void server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  router.all('/mcp', manage, (_req, res) => { res.set('Allow', 'POST').status(405).end(); });
  if (shells) router.post('/api/v1/sessions/:id/shells', manage, (req, res) => { res.status(201).json(shells.create(Id.parse(req.params.id), req.body)); });
  if (files) {
    router.put('/api/v1/sessions/:id/files', manage, async (req, res) => {
      if (!req.is('application/octet-stream')) throw new DomainError('INVALID_REQUEST', 400);
      const path = z.string().min(1).max(4096).parse(req.query.path);
      res.json(await files.transfer(Id.parse(req.params.id), path, 'upload', req));
    });
    router.get('/api/v1/sessions/:id/files', manage, async (req, res) => {
      const path = z.string().min(1).max(4096).parse(req.query.path);
      res.type('application/octet-stream');
      await files.transfer(Id.parse(req.params.id), path, 'download', res);
    });
  }
  router.post('/api/v1/invitations', manage, async (req, res) => { res.status(201).json(await service.createInvitation(req.body, requestKey(req))); });
  router.get('/api/v1/invitations/:id', manage, (req, res) => { res.json(service.invitation(Id.parse(req.params.id))); });
  router.post('/api/v1/invitations/:id/cancel', manage, async (req, res) => { res.json(await service.cancelInvitation(Id.parse(req.params.id))); });
  router.get('/api/v1/sessions', manage, (req, res) => {
    const offset = z.coerce.number().int().nonnegative().default(0).parse(req.query.offset), limit = z.coerce.number().int().min(1).max(100).default(20).parse(req.query.limit);
    const items = service.list(); res.json({ items: items.slice(offset, offset + limit), nextOffset: offset + limit < items.length ? offset + limit : null });
  });
  router.get('/api/v1/sessions/:id', manage, (req, res) => { res.json(service.summary(Id.parse(req.params.id))); });
  router.get('/api/v1/sessions/:id/metrics', manage, (req, res) => { const id = Id.parse(req.params.id); res.json(service.transport?.metrics(id) ?? service.savedMetrics(id)); });
  if (operations) {
    router.post('/api/v1/sessions/:id/executions', manage, async (req, res) => { res.status(202).json(await operations.start(Id.parse(req.params.id), req.body, requestKey(req))); });
    router.get('/api/v1/executions/:id', manage, (req, res) => { res.json(operations.get(Id.parse(req.params.id))); });
    router.post('/api/v1/executions/:id/cancel', manage, (req, res) => { res.json(operations.cancel(Id.parse(req.params.id))); });
  }
  router.get('/api/v1/sessions/:id/ssh-config', manage, async (req, res) => {
    if (!native) throw new DomainError('OFFLINE', 503);
    res.json(await native.get(Id.parse(req.params.id)));
  });
  router.post('/api/v1/sessions/:id/disconnect', manage, async (req, res) => { res.json(await service.disconnect(Id.parse(req.params.id), 's_operator')); });
  router.get('/api/v1/browser/context', (req, res) => { const value = browser(req, res, true); res.json({ csrf: csrf(value) }); });
  router.get('/api/v1/browser/invitation', (req, res) => { const value = browser(req, res, true); res.json({ ...service.invitationPage(Credential.parse(req.query.code), hash(value)), csrf: csrf(value) }); });
  router.post('/api/v1/invitations/accept', browserWrite, async (req, res) => {
    const data = z.object({ code: Credential, consent: z.literal(true) }).strict().parse(req.body);
    res.json(await service.accept(data.code, res.locals.browserHash, requestKey(req)));
  });
  router.get('/api/v1/browser/session', (req, res) => { const value = browser(req, res); res.json({ ...service.browserSession(hash(value)), csrf: csrf(value) }); });
  router.post('/api/v1/browser/bootstrap', browserWrite, async (req, res) => { res.json(await service.bootstrap(res.locals.browserHash, requestKey(req))); });
  router.post('/api/v1/browser/connection-script', browserWrite, async (req, res) => {
    if (!artifacts) throw new DomainError('OFFLINE', 503);
    const { platform } = z.object({ platform: z.enum(['win32', 'linux']) }).strict().parse(req.body);
    const boot = await service.bootstrap(res.locals.browserHash, requestKey(req));
    res.attachment(`NyaaRink-${boot.sessionId}.${platform === 'win32' ? 'bat' : 'sh'}`).type('text/plain').send(connectionScript(boot, artifacts.get(platform)));
  });
  router.post('/api/v1/browser/disconnect', browserWrite, async (req, res) => {
    const { sessionId } = z.object({ sessionId: Id }).strict().parse(req.body);
    res.json(await service.disconnect(sessionId, 'c_browser', res.locals.browserHash));
  });
  router.post('/api/v1/browser/recovery', limit('recovery', 5), browserWrite, (_req, res) => { res.json(service.recovery(res.locals.browserHash)); });
  router.post('/api/v1/device/enroll', limit('enroll', 30), async (req, res) => {
    const input = z.object({ data: z.unknown(), bootstrapKey: Credential, signature: z.string().max(256) }).strict().parse(req.body);
    res.json(await service.enroll(input.data, input.bootstrapKey, input.signature));
  });
  router.post('/api/v1/device/challenge', limit('challenge', 120), (req, res) => {
    const input = z.object({ sessionId: Id, operation: z.enum(['control', 'disconnect', 'cleanup-ack', 'recover-browser']) }).strict().parse(req.body);
    res.json(service.challenge(input.sessionId, input.operation));
  });
  router.post('/api/v1/device/disconnect', async (req, res) => { const input = Signed.strict().parse(req.body); res.json(await service.deviceDisconnect(input.sessionId, input.nonce, input.signature)); });
  router.post('/api/v1/device/cleanup-ack', async (req, res) => { const input = Signed.extend({ result: z.enum(['confirmed', 'failed']) }).strict().parse(req.body); res.json(await service.cleanupAck(input.sessionId, input.result, input.nonce, input.signature)); });
  router.post('/api/v1/device/recover-browser', async (req, res) => { const input = Signed.extend({ code: z.string().regex(/^[A-Z2-7]{12}$/) }).strict().parse(req.body); res.json(await service.recoverBrowser(input.sessionId, input.code, input.nonce, input.signature)); });
  return router;
}
export function errorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (res.headersSent || res.destroyed) { res.destroy(); return; }
  const known = error instanceof DomainError, invalid = error instanceof z.ZodError || (error as { type?: string })?.type === 'entity.parse.failed';
  const large = (error as { type?: string })?.type === 'entity.too.large';
  res.status(known ? error.status : large ? 413 : invalid ? 400 : 500).json({ error: {
    code: known ? error.code : large ? 'LIMIT_EXCEEDED' : invalid ? 'INVALID_REQUEST' : 'INTERNAL',
    message: known ? error.code : invalid || large ? 'Invalid request' : 'Request could not be completed',
    retryable: known && ['FROZEN', 'OFFLINE', 'LIMIT_EXCEEDED'].includes(error.code), requestId: res.locals.requestId ?? randomUUID(),
  } });
}
