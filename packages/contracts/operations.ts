import { z } from 'zod';
export const ExecInput = z.object({
  command: z.string().min(1).max(16384), shell: z.enum(['posix', 'powershell', 'cmd']),
  cwd: z.string().min(1).max(4096).refine(value => !/[\0\r\n]/.test(value)).optional(),
  timeoutSeconds: z.number().int().min(1).max(3600).default(60),
}).strict();
export const ExecutionState = z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled', 'interrupted']);
export const ExecutionRecord = z.object({ id: z.uuid(), sessionId: z.uuid(), requestKey: z.string().regex(/^[a-f0-9]{64}$/), inputHash: z.string().regex(/^[a-f0-9]{64}$/), createdAt: z.iso.datetime() }).strict();
export const ExecutionResult = z.object({ id: z.uuid(), state: ExecutionState, exitCode: z.number().int().nullable() }).strict();
