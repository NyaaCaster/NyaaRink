import { z } from 'zod';
import { deviceMessage, deviceSign } from '../../server/src/crypto.js';
import type { State } from './state.js';

export class ApiError extends Error { constructor(readonly status: number, readonly code: string) { super(`S端请求失败 (${status}, ${code})`); } }
export class DeviceApi {
  constructor(readonly state: State, readonly request: typeof fetch = fetch) {}
  async post(path: string, body: unknown): Promise<unknown> {
    const url = new URL(path, this.state.bootstrap.origin);
    if (url.origin !== this.state.bootstrap.origin || url.protocol !== 'https:') throw new Error('Invalid API origin');
    const response = await this.request(url, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
    const reader = response.body?.getReader();
    if (!reader) throw new Error('Empty API response');
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        length += value.length;
        if (length > 32768) { await reader.cancel(); throw new Error('API response too large'); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!response.ok) throw new ApiError(response.status, String(data?.error?.code ?? 'UNKNOWN'));
    return data;
  }
  async signed(operation: 'disconnect' | 'cleanup-ack' | 'recover-browser' | 'control', body: Record<string, unknown> = {}) {
    if (!this.state.devicePrivateKey) throw new Error('Device key has been destroyed');
    const sessionId = this.state.bootstrap.sessionId;
    const challenge = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), v: z.literal(1), instanceId: z.string().uuid(), epoch: z.string().uuid() }).strict()
      .parse(await this.post('/api/v1/device/challenge', { sessionId, operation }));
    const { instanceId, epoch } = this.state.bootstrap;
    if (challenge.instanceId !== instanceId || challenge.epoch !== epoch) throw new Error('S端实例身份改变；访问冻结');
    const signature = deviceSign(this.state.devicePrivateKey, deviceMessage(operation, instanceId, epoch, sessionId, challenge.nonce, body));
    return { sessionId, nonce: challenge.nonce, signature, ...body };
  }
  async perform(operation: 'disconnect' | 'cleanup-ack' | 'recover-browser', body: Record<string, unknown> = {}) {
    return this.post('/api/v1/device/' + operation, await this.signed(operation, body));
  }
}
