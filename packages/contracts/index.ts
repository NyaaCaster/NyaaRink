import { z } from 'zod';
export const SessionId = z.string().uuid();
export const InvitationInput = z.object({
  helperName: z.string().trim().min(1).max(128),
  purpose: z.string().trim().min(1).max(1024),
}).strict();
export const AcceptInput = z.object({ requestId: z.string().uuid(), consent: z.literal(true) }).strict();
export const Authorization = z.enum(['accepted', 'enrolled', 'revoked']);
export const Connection = z.enum(['waiting', 'online', 'offline', 'reconnecting']);
export const Cleanup = z.enum(['not_needed', 'pending', 'confirmed', 'failed']);
export const ErrorCode = z.enum(['UNAUTHORIZED', 'INVALID_REQUEST', 'INVITATION_UNAVAILABLE', 'CONFLICT', 'REVOKED', 'FROZEN', 'OFFLINE', 'LIMIT_EXCEEDED', 'NOT_FOUND', 'INTERNAL']);
export class DomainError extends Error {
  constructor(public readonly code: z.infer<typeof ErrorCode>, public readonly status = 400) { super(code); }
}
export const DEFAULTS = Object.freeze({
  invitationMs: 24 * 3600_000, bootstrapMs: 10 * 60_000,
  maxSessions: 20, maxStreams: 4, heartbeatMs: 15000, offlineMs: 45000,
  maxExecSeconds: 3600, execSeconds: 60, maxOutputBytes: 1024 * 1024,
  maxFileBytes: 100 * 1024 * 1024, resultRetentionMs: 10 * 60_000,
});
