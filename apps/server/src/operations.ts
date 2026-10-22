import { z } from 'zod';
import { DEFAULTS, DomainError } from '@nyaarink/contracts';
import { ExecInput, ExecutionState } from '../../../packages/contracts/operations.js';
import { hash } from './crypto.js';
import type { TunnelHub } from './tunnel.js';
import type { Client, ClientChannel } from 'ssh2';

const posix = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
export function executionCommand(input: z.infer<typeof ExecInput>, platform: string) {
  if ((platform === 'win32') === (input.shell === 'posix')) throw new DomainError('INVALID_REQUEST', 400);
  if (input.shell === 'posix') return 'sh -c ' + posix((input.cwd ? 'cd -- ' + posix(input.cwd) + ' && ' : '') + 'exec sh -c ' + posix(input.command));
  if (input.shell === 'powershell') {
    const script = "$ErrorActionPreference='Stop'; " + (input.cwd ? "Set-Location -LiteralPath '" + input.cwd.replaceAll("'", "''") + "'; " : '') + input.command;
    return 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ' + Buffer.from(script, 'utf16le').toString('base64');
  }
  if (input.cwd && /[&|<>^%!"\r\n]/.test(input.cwd)) throw new DomainError('INVALID_REQUEST', 400);
  return 'cmd.exe /d /s /c "' + (input.cwd ? 'cd /d "' + input.cwd + '" && ' : '') + input.command + '"';
}
type Task = { id: string; sessionId: string; state: z.infer<typeof ExecutionState>; stdout: Buffer[]; stderr: Buffer[]; bytes: number; truncated: boolean; exitCode: number | null; expiresAt: string; client?: Client; channel?: ClientChannel; timer?: NodeJS.Timeout; done?: Promise<void> };
export class Operations {
  private tasks = new Map<string, Task>();
  private reservations = 0;
  private prune: NodeJS.Timeout;
  constructor(readonly hub: TunnelHub) {
    hub.service.on('revoke', this.revoke);
    this.prune = setInterval(() => {
      for (const [id, task] of this.tasks) if (!['queued', 'running'].includes(task.state) && Date.parse(task.expiresAt) <= Date.now()) this.tasks.delete(id);
    }, 30000);
  }
  async start(sessionId: string, raw: unknown, requestId: string) {
    const input = ExecInput.parse(raw), device = this.hub.service.credentials(sessionId).device;
    const command = executionCommand(input, device.platform);
    let reserved = false;
    let accepted: Awaited<ReturnType<typeof this.hub.service.acceptExecution>>;
    try {
      accepted = await this.hub.service.acceptExecution(sessionId, hash(JSON.stringify(input)), requestId, () => {
        if ([...this.tasks.values()].filter(task => ['queued', 'running'].includes(task.state)).length + this.reservations >= 32 || this.tasks.size + this.reservations >= 128) throw new DomainError('LIMIT_EXCEEDED', 429);
        this.reservations++; reserved = true;
      });
    } finally { if (reserved) this.reservations--; }
    if (accepted.replay) return this.get(accepted.record.id);
    const task: Task = { id: accepted.record.id, sessionId, state: 'queued', stdout: [], stderr: [], bytes: 0, truncated: false, exitCode: null, expiresAt: new Date(Date.now() + DEFAULTS.resultRetentionMs).toISOString() };
    this.tasks.set(task.id, task); this.hub.operation(sessionId);
    task.done = this.run(task, command, input.timeoutSeconds); return this.get(task.id);
  }
  get(id: string) {
    const record = this.hub.service.executions.get(id); if (!record) throw new DomainError('NOT_FOUND', 404);
    const task = this.tasks.get(id), retained = task && (['queued', 'running'].includes(task.state) || Date.parse(task.expiresAt) > Date.now());
    return { executionId: id, sessionId: record.sessionId, state: task?.state ?? record.state, exitCode: task?.exitCode ?? record.exitCode,
      stdout: retained ? Buffer.concat(task.stdout).toString('utf8') : '', stderr: retained ? Buffer.concat(task.stderr).toString('utf8') : '',
      truncated: task?.truncated ?? false, outputExpired: !retained, expiresAt: task?.expiresAt ?? null };
  }
  private async run(task: Task, command: string, timeout: number) {
    try {
      task.timer = setTimeout(() => this.interrupt(task, 'cancelled'), timeout * 1000);
      const client = await this.hub.connect(task.sessionId); task.client = client;
      if (task.state !== 'queued') { client.destroy(); return; }
      task.state = 'running';
      await new Promise<void>((ok, fail) => {
        client.once('close', () => { if (task.state === 'running') task.state = 'interrupted'; ok(); });
        client.exec(command, (error, channel) => {
          if (error) { fail(error); return; } task.channel = channel;
          const collect = (target: Buffer[], bytes: Buffer) => { const remaining = DEFAULTS.maxOutputBytes - task.bytes; if (bytes.length > remaining) task.truncated = true; if (remaining > 0) { const part = Buffer.from(bytes.subarray(0, remaining)); target.push(part); task.bytes += part.length; } };
          channel.on('data', (bytes: Buffer) => collect(task.stdout, bytes)); channel.stderr.on('data', (bytes: Buffer) => collect(task.stderr, bytes));
          channel.on('error', fail); channel.once('close', (code: number | undefined) => {
            if (task.state === 'running') { task.exitCode = code ?? null; task.state = code === 0 ? 'succeeded' : code === undefined ? 'interrupted' : 'failed'; } ok();
          });
        });
      });
    } catch { if (['queued', 'running'].includes(task.state)) task.state = 'failed'; }
    finally {
      clearTimeout(task.timer); task.client?.destroy(); task.expiresAt = new Date(Date.now() + DEFAULTS.resultRetentionMs).toISOString();
      try { await this.hub.service.finishExecution(task.id, task.state, task.exitCode); } catch { /* Frozen authority rejects future access. No replay. */ }
    }
  }
  private interrupt(task: Task, state: 'cancelled' | 'interrupted') {
    if (!['queued', 'running'].includes(task.state)) return;
    task.state = state; task.channel?.signal('TERM'); task.channel?.destroy(); task.client?.destroy();
  }
  cancel(id: string) { this.get(id); const task = this.tasks.get(id); if (task) this.interrupt(task, 'cancelled'); return this.get(id); }
  private revoke = (id: string) => { for (const task of this.tasks.values()) if (task.sessionId === id) this.interrupt(task, 'interrupted'); };
  async close() { clearInterval(this.prune); this.hub.service.off('revoke', this.revoke); for (const task of this.tasks.values()) this.interrupt(task, 'interrupted'); await Promise.all([...this.tasks.values()].map(task => task.done)); this.tasks.clear(); }
}
