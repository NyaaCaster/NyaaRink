import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { utils } from 'ssh2';
import { z } from 'zod';
import { DEFAULTS, DomainError, InvitationInput } from '@nyaarink/contracts';
import { Authority, type AuthorityEvent } from './authority.js';
import { Projection } from './projection.js';
import { deviceMessage, deviceVerify, equal, hash, token } from './crypto.js';

const Id = z.string().uuid(), Digest = z.string().regex(/^[a-f0-9]{64}$/), Time = z.iso.datetime();
export const Enrollment = z.object({ sessionId: Id, enrollmentId: Id, devicePublicKey: z.string().max(1024),
  account: z.string().min(1).max(128).regex(/^[^\x00-\x1f\x7f]+$/), home: z.string().min(1).max(4096),
  shell: z.enum(['posix', 'powershell', 'cmd']), platform: z.enum(['linux', 'win32']),
  host: z.enum(['127.0.0.1', '::1']), port: z.number().int().min(1).max(65535),
  hostKeys: z.array(z.string().min(32).max(4096).regex(/^[A-Za-z0-9+/]+={0,2}$/)).min(1).max(8),
}).strict();
export type EnrollmentData = z.infer<typeof Enrollment>;
const Invite = InvitationInput.extend({ id: Id, codeHash: Digest, expiresAt: Time, requestKey: Digest, inputHash: Digest });
type Invitation = z.infer<typeof Invite> & { state: 'issued' | 'consumed' | 'cancelled'; sessionId?: string };
type Session = { id: string; inviteId: string; browserHash: string; acceptedAt: string; authorization: 'accepted' | 'enrolled' | 'revoked';
  requestKey: string; inputHash: string; bootstrap?: { hash: string; enrollmentId: string; expiresAt: string; secretId: string };
  device?: EnrollmentData; revokedAt?: string; actor?: string; sCleanup: 'not_needed' | 'pending' | 'confirmed' | 'failed'; cCleanup: 'not_needed' | 'pending' | 'confirmed' | 'failed' };
type SessionSecret = { sshPrivate: string; sshPublic: string };
export const Payloads = {
  invitation: Invite,
  cancel: z.object({ inviteId: Id }).strict(),
  accept: z.object({ inviteId: Id, id: Id, browserHash: Digest, requestKey: Digest, inputHash: Digest }).strict(),
  bootstrap: z.object({ id: Id, hash: Digest, enrollmentId: Id, expiresAt: Time, secretId: Id, requestKey: Digest, inputHash: Digest }).strict(),
  enroll: z.object({ data: Enrollment, bootstrapHash: Digest }).strict(),
  revoke: z.object({ id: Id, actor: z.enum(['s_operator', 'c_browser', 'c_local']), nonceHash: Digest.optional() }).strict(),
  cleanup: z.object({ id: Id, result: z.enum(['confirmed', 'failed']), nonceHash: Digest }).strict(),
  browser: z.object({ id: Id, browserHash: Digest, nonceHash: Digest }).strict(),
};
type EventType = keyof typeof Payloads;
export class RinkService extends EventEmitter {
  readonly invitations = new Map<string, Invitation>();
  readonly sessions = new Map<string, Session>();
  private idempotency = new Map<string, { inputHash: string; sessionId: string; secretId?: string }>();
  private queue: Promise<unknown> = Promise.resolve();
  private challenges = new Map<string, { sessionId: string; operation: string; until: number }>();
  private recoveries = new Map<string, { browserHash: string; until: number; attempts: number }>();
  private usedNonces = new Set<string>();
  private constructor(readonly authority: Authority, readonly projection: Projection, readonly origin: string) { super(); }
  static async open(authority: Authority, directory: string, origin: string) {
    const projection = await Projection.open(directory, authority);
    const service = new RinkService(authority, projection, origin);
    try {
      for (const event of authority.events) service.reduce(event);
      for (const i of service.invitations.values()) if (i.state === 'issued' && Date.parse(i.expiresAt) > Date.now()) authority.secret(i.id);
      for (const s of service.sessions.values()) {
        if (s.authorization === 'accepted' && s.bootstrap && Date.parse(s.bootstrap.expiresAt) > Date.now()) authority.secret(s.bootstrap.secretId);
        if (s.authorization === 'enrolled') {
          const secret = authority.secret<SessionSecret>(s.id);
          if (!secret.sshPrivate || !secret.sshPublic) throw new Error('Missing SSH secret');
        }
        if (s.authorization === 'revoked') service.cleanServer(s);
      }
      projection.write(authority, service.snapshot()); // open() backed up before schema/projection writes.
      return service;
    } catch (error) { authority.freeze('STATE_REPLAY_FAILED'); projection.close(); throw error; }
  }
  private snapshot() { return { invitations: [...this.invitations.values()], sessions: [...this.sessions.values()] }; }
  private reduce(event: AuthorityEvent) {
    const type = event.type as EventType;
    if (!Object.hasOwn(Payloads, type)) throw new Error('Unknown event');
    const p = Payloads[type].parse(event.payload);
    if (type === 'invitation') {
      const data = Payloads.invitation.parse(p);
      if (this.invitations.has(data.id)) throw new Error('Duplicate invitation');
      this.invitations.set(data.id, { ...data, state: 'issued' }); return;
    }
    if (type === 'cancel') {
      const { inviteId } = Payloads.cancel.parse(p), invite = this.invitations.get(inviteId);
      if (!invite || invite.state !== 'issued') throw new Error('Invalid cancellation');
      invite.state = 'cancelled'; return;
    }
    if (type === 'accept') {
      const data = Payloads.accept.parse(p), invite = this.invitations.get(data.inviteId);
      if (!invite || invite.state !== 'issued' || this.sessions.has(data.id)) throw new Error('Invalid acceptance');
      invite.state = 'consumed'; invite.sessionId = data.id;
      this.sessions.set(data.id, { ...data, acceptedAt: event.time, authorization: 'accepted', sCleanup: 'not_needed', cCleanup: 'not_needed' });
      this.idempotency.set(data.requestKey, { inputHash: data.inputHash, sessionId: data.id }); return;
    }
    if (type === 'bootstrap') {
      const data = Payloads.bootstrap.parse(p), s = this.require(data.id);
      if (s.authorization !== 'accepted') throw new Error('Invalid bootstrap state');
      s.bootstrap = { hash: data.hash, enrollmentId: data.enrollmentId, expiresAt: data.expiresAt, secretId: data.secretId };
      this.idempotency.set(data.requestKey, { inputHash: data.inputHash, sessionId: s.id, secretId: data.secretId }); return;
    }
    if (type === 'enroll') {
      const { data, bootstrapHash } = Payloads.enroll.parse(p), s = this.require(data.sessionId);
      if (s.authorization !== 'accepted' || !s.bootstrap || !equal(s.bootstrap.hash, bootstrapHash) || s.bootstrap.enrollmentId !== data.enrollmentId) throw new Error('Invalid enrollment');
      s.device = data; s.authorization = 'enrolled'; return;
    }
    if (type === 'revoke') {
      const data = Payloads.revoke.parse(p), s = this.require(data.id);
      if (s.authorization === 'revoked') throw new Error('Duplicate revoke event');
      s.authorization = 'revoked'; s.revokedAt = event.time; s.actor = data.actor; s.cCleanup = s.device ? 'pending' : 'not_needed';
      if (data.nonceHash) this.usedNonces.add(data.nonceHash); return;
    }
    if (type === 'cleanup') {
      const data = Payloads.cleanup.parse(p), s = this.require(data.id);
      if (s.authorization !== 'revoked') throw new Error('Cleanup before revocation');
      s.cCleanup = data.result; this.usedNonces.add(data.nonceHash); return;
    }
    const data = Payloads.browser.parse(p), s = this.require(data.id);
    if (s.authorization === 'revoked') throw new Error('Recovery after revocation');
    s.browserHash = data.browserHash; this.usedNonces.add(data.nonceHash);
  }
  private require(id: string) { const s = this.sessions.get(id); if (!s) throw new DomainError('NOT_FOUND', 404); return s; }
  private async mutate<T>(fn: () => T): Promise<T> {
    const run = this.queue.then(async () => {
      this.authority.assertAvailable();
      const previousSeq = this.authority.events.length, previousState = JSON.stringify(this.snapshot());
      const result = fn();
      if (previousSeq === this.authority.events.length && previousState === JSON.stringify(this.snapshot())) return result;
      try { await this.projection.backup(this.authority); }
      catch { this.authority.freeze('BACKUP_FAILED'); throw new DomainError('FROZEN', 503); }
      this.authority.assertAvailable();
      try { this.projection.write(this.authority, this.snapshot()); }
      catch { this.authority.freeze('PROJECTION_WRITE_FAILED'); throw new DomainError('FROZEN', 503); }
      return result;
    });
    this.queue = run.catch(() => {}); return run;
  }
  private commit(type: EventType, payload: Record<string, unknown>) {
    Payloads[type].parse(payload);
    const event = this.authority.append(type, payload);
    try { this.reduce(event); } catch { this.authority.freeze('EVENT_REDUCER_FAILED'); throw new DomainError('FROZEN', 503); }
    this.emit('change', event); return event;
  }
  private key(scope: string, id: string) { Id.parse(id); return hash(scope + ':' + id); }
  async createInvitation(input: unknown, requestId: string) {
    const data = InvitationInput.parse(input), inputHash = hash(JSON.stringify(data)), requestKey = this.key('create', requestId);
    return this.mutate(() => {
      const existing = [...this.invitations.values()].find(i => i.requestKey === requestKey);
      if (existing) {
        if (existing.inputHash !== inputHash) throw new DomainError('CONFLICT', 409);
        if (existing.state !== 'issued') throw new DomainError('INVITATION_UNAVAILABLE', 404);
        return this.invitationResult(existing);
      }
      const id = randomUUID(), code = token(), expiresAt = new Date(Date.now() + DEFAULTS.invitationMs).toISOString();
      this.authority.saveSecret(id, { code });
      this.commit('invitation', { ...data, id, codeHash: hash(code), expiresAt, requestKey, inputHash });
      return { inviteId: id, inviteUrl: this.origin + '/' + code, expiresAt };
    });
  }
  private invitationResult(i: Invitation) { const secret = this.authority.secret<{ code: string }>(i.id); return { inviteId: i.id, inviteUrl: this.origin + '/' + secret.code, expiresAt: i.expiresAt }; }
  invitation(id: string) { const i = this.invitations.get(id); if (!i) throw new DomainError('NOT_FOUND', 404); return { inviteId: i.id, helperName: i.helperName, purpose: i.purpose, state: i.state === 'issued' && Date.parse(i.expiresAt) <= Date.now() ? 'expired' : i.state, expiresAt: i.expiresAt }; }
  invitationPage(code: string, browserHash: string) {
    this.authority.assertAvailable();
    const i = [...this.invitations.values()].find(i => equal(i.codeHash, hash(code)));
    if (!i) throw new DomainError('INVITATION_UNAVAILABLE', 404);
    if (i.state === 'consumed' && i.sessionId) {
      const s = this.require(i.sessionId);
      if (s.authorization !== 'revoked' && equal(s.browserHash, browserHash)) return this.summary(s.id);
    }
    if (i.state !== 'issued' || Date.parse(i.expiresAt) <= Date.now()) throw new DomainError('INVITATION_UNAVAILABLE', 404);
    return { helperName: i.helperName, purpose: i.purpose, expiresAt: i.expiresAt, state: 'issued' };
  }
  cancelInvitation(id: string) { return this.mutate(() => { const i = this.invitations.get(id); if (!i) throw new DomainError('NOT_FOUND', 404); if (i.state === 'consumed') throw new DomainError('CONFLICT', 409); if (i.state === 'issued') this.commit('cancel', { inviteId: id }); this.authority.deleteSecret(id); return { state: 'cancelled' }; }); }
  accept(code: string, browserHash: string, requestId: string) {
    const requestKey = this.key('accept:' + browserHash, requestId), inputHash = hash(code);
    return this.mutate(() => {
      const old = this.idempotency.get(requestKey);
      if (old) { if (old.inputHash !== inputHash) throw new DomainError('CONFLICT', 409); return this.activeSummary(old.sessionId); }
      const i = [...this.invitations.values()].find(i => equal(i.codeHash, hash(code)));
      if (!i || i.state !== 'issued' || Date.parse(i.expiresAt) <= Date.now()) throw new DomainError('INVITATION_UNAVAILABLE', 404);
      if ([...this.sessions.values()].some(s => s.authorization !== 'revoked' && equal(s.browserHash, browserHash))) throw new DomainError('CONFLICT', 409);
      if ([...this.sessions.values()].filter(s => s.authorization !== 'revoked').length >= DEFAULTS.maxSessions) throw new DomainError('LIMIT_EXCEEDED', 429);
      const id = randomUUID(); this.commit('accept', { inviteId: i.id, id, browserHash, requestKey, inputHash });
      this.authority.deleteSecret(i.id); return this.summary(id);
    });
  }
  browserSession(browserHash: string) {
    this.authority.assertAvailable();
    const s = [...this.sessions.values()].find(s => s.authorization !== 'revoked' && equal(s.browserHash, browserHash));
    if (!s) throw new DomainError('NOT_FOUND', 404); return this.summary(s.id);
  }
  bootstrap(browserHash: string, requestId: string) {
    return this.mutate(() => {
      const s = this.browserSession(browserHash), state = this.require(s.id);
      if (state.authorization !== 'accepted') throw new DomainError('CONFLICT', 409);
      const requestKey = this.key('bootstrap:' + browserHash, requestId), old = this.idempotency.get(requestKey);
      if (old) {
        if (old.secretId !== state.bootstrap?.secretId) throw new DomainError('CONFLICT', 409);
        return this.authority.secret<Record<string, string>>(old.secretId!);
      }
      const bootstrapKey = token(), enrollmentId = randomUUID(), secretId = randomUUID(), expiresAt = new Date(Date.now() + DEFAULTS.bootstrapMs).toISOString();
      const result = { sessionId: s.id, enrollmentId, bootstrapKey, expiresAt, origin: this.origin, ...this.authority.identity };
      this.authority.saveSecret(secretId, result);
      const previous = state.bootstrap?.secretId;
      this.commit('bootstrap', { id: s.id, hash: hash(bootstrapKey), enrollmentId, expiresAt, secretId, requestKey, inputHash: hash(s.id) });
      if (previous) this.authority.deleteSecret(previous);
      return result;
    });
  }
  enroll(input: unknown, bootstrapKey: string, signature: string) {
    const data = Enrollment.parse(input), { instanceId, epoch } = this.authority.identity;
    if (!deviceVerify(data.devicePublicKey, deviceMessage('enroll', instanceId, epoch, data.sessionId, hash(bootstrapKey), data), signature)) throw new DomainError('UNAUTHORIZED', 401);
    return this.mutate(() => {
      const s = this.require(data.sessionId);
      if (s.authorization === 'revoked') throw new DomainError('REVOKED', 410);
      if (s.authorization === 'enrolled') {
        if (JSON.stringify(data) !== JSON.stringify(s.device)) throw new DomainError('CONFLICT', 409);
        return this.enrollmentResult(s.id);
      }
      if (!s.bootstrap || !equal(s.bootstrap.hash, hash(bootstrapKey)) || s.bootstrap.enrollmentId !== data.enrollmentId || Date.parse(s.bootstrap.expiresAt) <= Date.now()) throw new DomainError('UNAUTHORIZED', 401);
      const pair = utils.generateKeyPairSync('ed25519');
      this.authority.saveSecret(s.id, { sshPrivate: pair.private, sshPublic: pair.public });
      this.commit('enroll', { data, bootstrapHash: hash(bootstrapKey) });
      this.authority.deleteSecret(s.bootstrap.secretId); return this.enrollmentResult(s.id);
    });
  }
  private enrollmentResult(id: string) { return { sessionId: id, ...this.authority.identity, sshPublicKey: this.authority.secret<SessionSecret>(id).sshPublic }; }
  activeSummary(id: string) { this.authority.assertAvailable(); const s = this.require(id); if (s.authorization === 'revoked') throw new DomainError('REVOKED', 410); return this.summary(id); }
  summary(id: string) {
    const s = this.require(id), invitation = this.invitations.get(s.inviteId)!;
    return { id, authorization: s.authorization, acceptedAt: s.acceptedAt, revokedAt: s.revokedAt,
      connectivity: s.device ? 'offline' : 'waiting', frozen: this.authority.frozen, helperName: invitation.helperName, purpose: invitation.purpose,
      account: s.device?.account, platform: s.device?.platform, sCleanup: s.sCleanup, cCleanup: s.cCleanup };
  }
  list() { return [...this.sessions.keys()].map(id => this.summary(id)); }
  credentials(id: string) { this.activeSummary(id); const s = this.require(id); if (!s.device) throw new DomainError('OFFLINE', 503); return { ...this.authority.secret<SessionSecret>(id), device: s.device }; }
  private cleanServer(s: Session) {
    try {
      this.authority.deleteSecret(s.id); this.authority.deleteSecret(s.inviteId);
      // Remove every historical bootstrap response, including a crash-orphaned replacement.
      for (const old of this.idempotency.values()) if (old.sessionId === s.id && old.secretId) this.authority.deleteSecret(old.secretId);
      s.sCleanup = 'confirmed';
    } catch { s.sCleanup = 'failed'; }
  }
  disconnect(id: string, actor: 's_operator' | 'c_browser' | 'c_local', browserHash?: string, nonceHash?: string) {
    return this.mutate(() => {
      const s = this.require(id);
      if (actor === 'c_browser' && (!browserHash || !equal(s.browserHash, browserHash))) throw new DomainError('NOT_FOUND', 404);
      if (s.authorization !== 'revoked') this.commit('revoke', { id, actor, ...(nonceHash ? { nonceHash } : {}) });
      // Subscribers close channels synchronously; cleanup never rolls back the durable revoke.
      this.emit('revoke', id); this.cleanServer(s);
      return { authorization: 'revoked', accessClosed: true, sCleanup: s.sCleanup, cCleanup: s.cCleanup };
    });
  }
  challenge(sessionId: string, operation: string) {
    this.authority.assertAvailable(); const s = this.require(sessionId);
    if (!s.device || !['control', 'disconnect', 'cleanup-ack', 'recover-browser'].includes(operation)) throw new DomainError('UNAUTHORIZED', 401);
    if (s.authorization === 'revoked' && !['disconnect', 'cleanup-ack'].includes(operation)) throw new DomainError('REVOKED', 410);
    this.expireTransient(); if (this.challenges.size >= 1000) throw new DomainError('LIMIT_EXCEEDED', 429);
    const nonce = token(); this.challenges.set(hash(nonce), { sessionId, operation, until: Date.now() + 30000 });
    return { nonce, ...this.authority.identity };
  }
  verifyDevice(sessionId: string, operation: string, nonce: string, body: unknown, signature: string) {
    this.authority.assertAvailable(); const s = this.require(sessionId), nonceHash = hash(nonce), challenge = this.challenges.get(nonceHash);
    if (!s.device || !challenge || challenge.until <= Date.now() || challenge.sessionId !== sessionId || challenge.operation !== operation || this.usedNonces.has(nonceHash)) throw new DomainError('UNAUTHORIZED', 401);
    const { instanceId, epoch } = this.authority.identity;
    if (!deviceVerify(s.device.devicePublicKey, deviceMessage(operation, instanceId, epoch, sessionId, nonce, body), signature)) throw new DomainError('UNAUTHORIZED', 401);
    this.challenges.delete(nonceHash); return nonceHash;
  }
  deviceDisconnect(id: string, nonce: string, signature: string) { const digest = this.verifyDevice(id, 'disconnect', nonce, {}, signature); return this.disconnect(id, 'c_local', undefined, digest); }
  cleanupAck(id: string, result: 'confirmed' | 'failed', nonce: string, signature: string) {
    const nonceHash = this.verifyDevice(id, 'cleanup-ack', nonce, { result }, signature);
    return this.mutate(() => { this.commit('cleanup', { id, result, nonceHash }); return this.summary(id); });
  }
  recovery(browserHash: string) {
    this.expireTransient(); if (this.recoveries.size >= 1000) throw new DomainError('LIMIT_EXCEEDED', 429);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', bytes = Buffer.from(token(), 'base64url');
    const code = [...bytes.subarray(0, 12)].map(byte => alphabet[byte & 31]).join('');
    this.recoveries.set(hash(code), { browserHash, until: Date.now() + 300000, attempts: 0 }); return { code, expiresInSeconds: 300 };
  }
  recoverBrowser(id: string, code: string, nonce: string, signature: string) {
    const nonceHash = this.verifyDevice(id, 'recover-browser', nonce, { code }, signature);
    return this.mutate(() => {
      const challenge = this.recoveries.get(hash(code));
      if (!challenge || challenge.until <= Date.now() || ++challenge.attempts > 5) throw new DomainError('NOT_FOUND', 404);
      this.activeSummary(id);
      if ([...this.sessions.values()].some(s => s.id !== id && s.authorization !== 'revoked' && s.browserHash === challenge.browserHash)) throw new DomainError('CONFLICT', 409);
      this.commit('browser', { id, browserHash: challenge.browserHash, nonceHash }); this.recoveries.delete(hash(code)); return { recovered: true };
    });
  }
  private expireTransient() { const now = Date.now(); for (const [key, c] of this.challenges) if (c.until <= now) this.challenges.delete(key); for (const [key, c] of this.recoveries) if (c.until <= now) this.recoveries.delete(key); }
  async close() { await this.queue; this.projection.close(); this.authority.close(); }
}
