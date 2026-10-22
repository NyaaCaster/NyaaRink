import { Router, type Request, type Response, type NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { DomainError } from '@nyaarink/contracts';
import { RinkService } from './service.js';
import { equal, hash, mac, token } from './crypto.js';
import type { Config } from './config.js';

export type RouteConfig = Pick<Config, 'PUBLIC_BASE_URL' | 'MCP_API_KEY' | 'MCP_API_KEY_PREVIOUS' | 'API_KEY_PREVIOUS_UNTIL' | 'masterKey'>;
const Id = z.string().uuid();
const Credential = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const Signed = z.object({ sessionId: Id, nonce: Credential, signature: z.string().min(64).max(256) });
export function routes(service: RinkService, config: RouteConfig) {
  const router = Router(), buckets = new Map<string, { count: number; until: number }>();
  const origin = new URL(config.PUBLIC_BASE_URL).origin;
  const cookieKey = Buffer.from(mac(config.masterKey, 'browser-cookie-v1'), 'hex');
  const requestKey = (req: Request) => Id.parse(req.get('Idempotency-Key'));
  const csrf = (value: string) => mac(cookieKey, 'csrf:' + hash(value));
  const browser = (req: Request, res: Response, establish = false) => {
    const cookies = (req.headers.cookie ?? '').split(';').map(c => c.trim()).filter(c => c.startsWith('__Host-nr='));
    const value = cookies.length === 1 ? cookies[0]!.slice('__Host-nr='.length) : '';
    const parts = value.split('.');
    if (parts.length === 2 && Credential.safeParse(parts[0]).success && equal(parts[1]!, mac(cookieKey, parts[0]!))) return value;
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
  const manage = (req: Request, _res: Response, next: NextFunction) => {
    const header = req.get('authorization') ?? '', key = header.startsWith('Bearer ') ? header.slice(7) : '';
    const current = equal(hash(key), hash(config.MCP_API_KEY));
    const previous = !!config.MCP_API_KEY_PREVIOUS && Date.parse(config.API_KEY_PREVIOUS_UNTIL) > Date.now() && equal(hash(key), hash(config.MCP_API_KEY_PREVIOUS));
    if (!current && !previous) throw new DomainError('UNAUTHORIZED', 401); next();
  };
  const browserWrite = (req: Request, res: Response, next: NextFunction) => {
    const value = browser(req, res);
    if (req.get('origin') !== origin || !equal(req.get('X-NR-CSRF') ?? '', csrf(value))) throw new DomainError('UNAUTHORIZED', 403);
    res.locals.browserHash = hash(value); next();
  };
  router.post('/api/v1/invitations', manage, async (req, res) => { res.status(201).json(await service.createInvitation(req.body, requestKey(req))); });
  router.get('/api/v1/invitations/:id', manage, (req, res) => { res.json(service.invitation(Id.parse(req.params.id))); });
  router.post('/api/v1/invitations/:id/cancel', manage, async (req, res) => { res.json(await service.cancelInvitation(Id.parse(req.params.id))); });
  router.get('/api/v1/sessions', manage, (req, res) => {
    const offset = z.coerce.number().int().nonnegative().default(0).parse(req.query.offset), limit = z.coerce.number().int().min(1).max(100).default(20).parse(req.query.limit);
    const items = service.list(); res.json({ items: items.slice(offset, offset + limit), nextOffset: offset + limit < items.length ? offset + limit : null });
  });
  router.get('/api/v1/sessions/:id', manage, (req, res) => { res.json(service.summary(Id.parse(req.params.id))); });
  router.post('/api/v1/sessions/:id/disconnect', manage, async (req, res) => { res.json(await service.disconnect(Id.parse(req.params.id), 's_operator')); });
  router.get('/api/v1/browser/context', (req, res) => { const value = browser(req, res, true); res.json({ csrf: csrf(value) }); });
  router.get('/api/v1/browser/invitation', (req, res) => { const value = browser(req, res, true); res.json({ ...service.invitationPage(Credential.parse(req.query.code), hash(value)), csrf: csrf(value) }); });
  router.post('/api/v1/invitations/accept', browserWrite, async (req, res) => {
    const data = z.object({ code: Credential, consent: z.literal(true) }).strict().parse(req.body);
    res.json(await service.accept(data.code, res.locals.browserHash, requestKey(req)));
  });
  router.get('/api/v1/browser/session', (req, res) => { const value = browser(req, res); res.json({ ...service.browserSession(hash(value)), csrf: csrf(value) }); });
  router.post('/api/v1/browser/bootstrap', browserWrite, async (req, res) => { res.json(await service.bootstrap(res.locals.browserHash, requestKey(req))); });
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
  const known = error instanceof DomainError, invalid = error instanceof z.ZodError || (error as { type?: string })?.type === 'entity.parse.failed';
  const large = (error as { type?: string })?.type === 'entity.too.large';
  res.status(known ? error.status : large ? 413 : invalid ? 400 : 500).json({ error: {
    code: known ? error.code : large ? 'LIMIT_EXCEEDED' : invalid ? 'INVALID_REQUEST' : 'INTERNAL',
    message: known ? error.code : invalid || large ? 'Invalid request' : 'Request could not be completed',
    retryable: known && ['FROZEN', 'OFFLINE', 'LIMIT_EXCEEDED'].includes(error.code), requestId: res.locals.requestId ?? randomUUID(),
  } });
}
