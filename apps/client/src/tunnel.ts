import { connect as connectTcp, type Socket } from 'node:net';
import WebSocket, { createWebSocketStream, type ClientOptions } from 'ws';
import { z } from 'zod';
import { DEFAULTS } from '@nyaarink/contracts';
import { ControlMessage, Hello, message } from '../../../packages/contracts/tunnel.js';
import { Bandwidth, QueueBudget, bridge, DATA_LIMIT } from '../../../packages/contracts/transport.js';
import { deviceMessage, deviceSign } from '../../server/src/crypto.js';
import { StateStore } from './state.js';

// The injected connector is for isolated tests; production always uses verified
// WSS derived from the persisted HTTPS origin, without redirects.
export type Connector = (url: string, options: ClientOptions) => WebSocket;
export async function runTunnel(store: StateStore, revoke: () => Promise<unknown>, signal?: AbortSignal, connector: Connector = (url, options) => new WebSocket(url, options)) {
  const unlock = store.lock();
  let failures = 0;
  try {
    while (!signal?.aborted) {
      const state = store.read();
      if (['revoked', 'cleaned'].includes(state.phase)) break;
      if (state.phase !== 'ready' || !state.enrollment || !state.devicePrivateKey) throw new Error('本地安装未完成，不能建立隧道');
      const { epoch, instanceId, sessionId, origin } = state.bootstrap;
      const url = new URL('/api/v1/device/control', origin); url.protocol = 'wss:';
      const result = await new Promise<'offline' | 'revoked'>(resolve => {
        const ws = connector(url.href, { perMessageDeflate: false, maxPayload: 32768, followRedirects: false, handshakeTimeout: 15000 });
        const streams = new Set<WebSocket>(), sockets = new Set<Socket>();
        const bandwidth = new Bandwidth(), budget = new QueueBudget();
        let generation = 0, phase = 'challenge', last = Date.now(), revoked = false;
        const hello = Hello.parse({ protocolVersion: 1, devicePublicKey: state.devicePublicKey });
        const send = (type: Parameters<typeof message>[0], payload: unknown) => {
          if (ws.readyState === WebSocket.OPEN && ws.bufferedAmount <= 32768) ws.send(JSON.stringify(message(type, epoch, sessionId, generation, payload)));
          else ws.terminate();
        };
        const stop = () => ws.terminate();
        signal?.addEventListener('abort', stop, { once: true });
        const watch = setInterval(() => {
          if (store.revoked()) { revoked = true; ws.terminate(); }
          else if (Date.now() - last > DEFAULTS.offlineMs) ws.terminate();
        }, 1000);
        ws.on('open', () => send('hello', hello));
        ws.on('error', () => {});
        ws.on('message', (raw, binary) => {
          try {
            if (binary) throw new Error('Unexpected binary control');
            const input = ControlMessage.parse(JSON.parse(raw.toString()));
            if (input.epoch !== epoch || input.sessionId !== sessionId) throw new Error('Control identity mismatch');
            last = Date.now();
            if (phase === 'challenge') {
              if (input.type !== 'challenge' || input.generation !== 0) throw new Error('Challenge expected');
              const challenge = z.object({ nonce: z.string(), instanceId: z.literal(instanceId) }).parse(input.payload);
              phase = 'ready'; send('auth', { nonce: challenge.nonce, signature: deviceSign(state.devicePrivateKey!, deviceMessage('control', instanceId, epoch, sessionId, challenge.nonce, hello)) }); return;
            }
            if (phase === 'ready') {
              if (input.generation < 1 && input.type !== 'revoke') throw new Error('Invalid generation');
              generation = input.generation; phase = 'active';
              if (input.type === 'ready') { send('ready', { stage: 'local' }); return; }
            }
            if (input.generation !== generation || store.revoked()) throw new Error('Stale generation');
            if (input.type === 'revoke') { store.markRevoked(); revoked = true; ws.terminate(); return; }
            if (input.type === 'ping') { send('pong', input.payload); return; }
            if (input.type === 'ready') { failures = 0; return; }
            if (input.type === 'error') return;
            if (input.type !== 'open') throw new Error('Unexpected control');
            const { streamId, ticket } = z.object({ streamId: z.string().uuid(), ticket: z.string() }).parse(input.payload);
            if (streams.size >= DEFAULTS.maxStreams) { send('error', { streamId, code: 'LIMIT_EXCEEDED' }); return; }
            const dataUrl = new URL('/api/v1/device/streams/' + streamId, origin); dataUrl.protocol = 'wss:';
            const data = connector(dataUrl.href, { headers: { Authorization: 'Bearer ' + ticket }, perMessageDeflate: false, maxPayload: DATA_LIMIT, followRedirects: false, handshakeTimeout: 15000 });
            streams.add(data); data.on('error', () => {}); data.once('close', () => streams.delete(data));
            data.once('open', () => {
              if (store.revoked() || ws.readyState !== WebSocket.OPEN) { data.terminate(); return; }
              const local = state.enrollment!;
              if (!['127.0.0.1', '::1'].includes(local.host)) { data.terminate(); return; }
              const socket = connectTcp({ host: local.host, port: local.port }); sockets.add(socket);
              socket.on('error', () => data.terminate()); socket.once('close', () => sockets.delete(socket));
              const timeout = setTimeout(() => socket.destroy(), 10000); socket.once('connect', () => clearTimeout(timeout)); socket.once('close', () => clearTimeout(timeout));
              bridge(socket, createWebSocketStream(data, { highWaterMark: 65536 }), data, bandwidth, budget);
            });
          } catch { ws.close(1008, 'Control rejected'); }
        });
        ws.once('close', () => {
          clearInterval(watch); signal?.removeEventListener('abort', stop);
          for (const stream of streams) stream.terminate(); for (const socket of sockets) socket.destroy();
          resolve(revoked ? 'revoked' : 'offline');
        });
      });
      if (result === 'revoked' || store.revoked()) break;
      if (signal?.aborted) break;
      const wait = Math.min(30000, 1000 * 2 ** Math.min(failures++, 5)) * (0.8 + Math.random() * 0.4);
      await new Promise<void>(resolve => {
        const finish = () => { clearTimeout(timer); signal?.removeEventListener('abort', finish); resolve(); };
        const timer = setTimeout(finish, wait); signal?.addEventListener('abort', finish, { once: true });
      });
    }
  } finally { unlock(); }
  if (store.revoked()) await revoke();
}
