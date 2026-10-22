import { z } from 'zod';
const Id = z.string().uuid();
export const Bootstrap = z.object({ v: z.literal(1), sessionId: Id, enrollmentId: Id,
  bootstrapKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/), expiresAt: z.iso.datetime(),
  origin: z.url().refine(value => { const u = new URL(value); return u.protocol === 'https:' && u.origin === value && !u.username && !u.password; }),
  instanceId: Id, epoch: Id,
}).strict();
export type BootstrapData = z.infer<typeof Bootstrap>;
export const Enrollment = z.object({ sessionId: Id, enrollmentId: Id, devicePublicKey: z.string().max(1024),
  account: z.string().min(1).max(128).regex(/^[^\x00-\x1f\x7f]+$/), home: z.string().min(1).max(4096),
  shell: z.enum(['posix', 'powershell', 'cmd']), platform: z.enum(['linux', 'win32']),
  host: z.enum(['127.0.0.1', '::1']), port: z.number().int().min(1).max(65535),
  hostKeys: z.array(z.string().min(32).max(4096).regex(/^[A-Za-z0-9+/]+={0,2}$/)).min(1).max(8),
}).strict();
export type EnrollmentData = z.infer<typeof Enrollment>;
