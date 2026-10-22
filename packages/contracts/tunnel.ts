import { z } from 'zod';

const id = z.string().uuid(), credential = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const Hello = z.object({ protocolVersion: z.literal(1), devicePublicKey: z.string().max(1024) }).strict();
const payloads = {
  hello: Hello,
  challenge: z.object({ nonce: credential, instanceId: id }).strict(),
  auth: z.object({ nonce: credential, signature: z.string().max(256) }).strict(),
  ready: z.object({ stage: z.enum(['transport', 'local', 'verified']) }).strict(),
  open: z.object({ streamId: id, ticket: credential }).strict(),
  error: z.object({ streamId: id.optional(), code: z.string().max(64) }).strict(),
  status: z.object({ online: z.boolean() }).strict(),
  revoke: z.object({}).strict(),
  cleanup_ack: z.object({}).strict(),
  ping: z.object({ timestamp: z.number().finite().nonnegative() }).strict(),
  pong: z.object({ timestamp: z.number().finite().nonnegative() }).strict(),
};
const base = { v: z.literal(1), id, epoch: id, sessionId: id, generation: z.number().int().nonnegative() };
export const ControlMessage = z.object({ ...base, type: z.enum(Object.keys(payloads) as [keyof typeof payloads, ...(keyof typeof payloads)[]]), payload: z.unknown() }).strict()
  .superRefine((value, ctx) => { if (!payloads[value.type].safeParse(value.payload).success) ctx.addIssue({ code: 'custom', path: ['payload'], message: 'Invalid control payload' }); });
export type Message = z.infer<typeof ControlMessage>;
export function message(type: keyof typeof payloads, epoch: string, sessionId: string, generation: number, payload: unknown): Message {
  return ControlMessage.parse({ v: 1, id: crypto.randomUUID(), epoch, sessionId, generation, type, payload });
}
