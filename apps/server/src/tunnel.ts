import { randomUUID } from 'node:crypto';
import type { Server, IncomingMessage } from 'node:http';
import { PassThrough, Duplex } from 'node:stream';
import WebSocket, { WebSocketServer, createWebSocketStream } from 'ws';
import { z } from 'zod';
import { DomainError, DEFAULTS } from '@nyaarink/contracts';
import { ControlMessage, Hello, message } from '../../../packages/contracts/tunnel.js';
import { Bandwidth, QueueBudget, bridge, DATA_LIMIT } from '../../../packages/contracts/transport.js';
import { hash, token } from './crypto.js';
import { authenticated, checkCapabilities } from './ssh.js';
import type { RinkService } from './service.js';

type Peer = { ws: WebSocket; id: string; generation: number; last: number; ping?: number; verifiedAt?: number; verified: boolean; probing: boolean; bandwidth: Bandwidth };
type Pending = { id: string; generation: number; ticketHash: string; until: number; socket: Duplex; timer: NodeJS.Timeout; ws?: WebSocket };
type Counters = { sshBytesSToC: number; sshBytesCToS: number; sshConnectionsOpened: number; onlineSeconds: number; apiOperations: number; sshConnectionsActive: number; rttMs: number | null; sampledAt: string };
export class TunnelHub {
  private control = new WebSocketServer({ noServer: true, maxPayload: 32768, perMessageDeflate: false });
  private data = new WebSocketServer({ noServer: true, maxPayload: DATA_LIMIT, perMessageDeflate: false });
  private peers = new Map<string, Peer>();
  private streams = new Map<string, Pending>();
  private counters = new Map<string, Counters>();
  private budget = new QueueBudget();
  private heartbeat: NodeJS.Timeout;
  private checkpoint: NodeJS.Timeout;
  private saving?: Promise<void>;
  private attached?: Server;
  constructor(readonly service: RinkService) {
    service.transport = this;
    service.on('revoke', this.revoke);
    service.authority.on('frozen', this.freeze);
    this.heartbeat = setInterval(() => {
      for (const peer of this.peers.values()) {
        if (Date.now() - peer.last > DEFAULTS.offlineMs || service.authority.frozen) { peer.ws.terminate(); continue; }
        peer.ping = Date.now(); this.send(peer, 'ping', { timestamp: peer.ping });
      }
      // No authority transaction is required for transient availability. A
      // frozen authority must close existing streams as well as reject new ones.
      if (service.authority.frozen) for (const stream of this.streams.values()) stream.socket.destroy();
    }, DEFAULTS.heartbeatMs);
    this.checkpoint = setInterval(() => { void this.flush(); }, 10000);
  }
  flush(): Promise<void> {
    if (this.saving) return this.saving;
    if (this.service.authority.frozen) return Promise.resolve();
    this.saving = (async () => { try {
      for (const [id, value] of this.counters) {
        this.accountOnline(id);
        const { sshBytesSToC, sshBytesCToS, sshConnectionsOpened, onlineSeconds, apiOperations } = value;
        await this.service.saveMetrics(id, { sshBytesSToC, sshBytesCToS, sshConnectionsOpened, onlineSeconds, apiOperations });
      }
    } catch { /* The service freezes on persistence errors and closes streams. */ }
    finally { this.saving = undefined; } })();
    return this.saving;
  }
  private send(peer: Peer, type: Parameters<typeof message>[0], payload: unknown) {
    if (peer.ws.readyState === WebSocket.OPEN && peer.ws.bufferedAmount <= 32768) peer.ws.send(JSON.stringify(message(type, this.service.authority.identity.epoch, peer.id, peer.generation, payload)));
    else peer.ws.terminate();
  }
  metrics(id: string) {
    this.service.summary(id);
    let value = this.counters.get(id);
      if (!value) { value = { ...this.service.savedMetrics(id), sshConnectionsActive: 0, rttMs: null, sampledAt: new Date().toISOString() }; this.counters.set(id, value); }
    this.accountOnline(id);
    const session = this.service.sessions.get(id)!;
    return { ...value, authorizedSeconds: Math.max(0, (Date.parse(session.revokedAt ?? new Date().toISOString()) - Date.parse(session.acceptedAt)) / 1000), rttMs: this.peers.has(id) ? value.rttMs : null };
  }
  operation(id: string) { this.metrics(id); this.counters.get(id)!.apiOperations++; }
  online(id: string) { return this.peers.get(id)?.verified === true && !this.service.authority.frozen; }
  attach(server: Server) { if (this.attached) throw new Error('Hub already attached'); this.attached = server; server.on('upgrade', this.upgrade); }
  private upgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    if (req.url?.startsWith('/api/v1/shells/') || req.url === '/api/v1/browser/events') return;
    socket.on('error', () => {});
    try {
      const origin = new URL(this.service.origin);
      if (req.headers.host !== origin.host || (req.headers.origin && req.headers.origin !== origin.origin) || req.headers['sec-websocket-protocol']) throw new Error('Origin mismatch');
      this.service.authority.assertAvailable();
      if (req.url === '/api/v1/device/control') {
        if (this.control.clients.size >= 40) throw new Error('Control limit');
        this.control.handleUpgrade(req, socket, head, ws => this.acceptControl(ws)); return;
      }
      const match = /^\/api\/v1\/device\/streams\/([a-f0-9-]{36})$/.exec(req.url ?? '');
      if (!match) throw new Error('Unknown route');
      const stream = this.streams.get(match[1]!);
      if (!stream || stream.ws || stream.until <= Date.now() || !/^Bearer [A-Za-z0-9_-]{43}$/.test(req.headers.authorization ?? '') || hash(req.headers.authorization!.slice(7)) !== stream.ticketHash) throw new Error('Ticket rejected');
      const peer = this.peers.get(stream.id);
      this.service.activeSummary(stream.id);
      if (!peer || peer.generation !== stream.generation) throw new Error('Generation mismatch');
      // Consume before upgrade, including a malformed handshake. Never reuse.
      stream.ticketHash = '';
      this.data.handleUpgrade(req, socket, head, ws => {
        stream.ws = ws;
        clearTimeout(stream.timer);
        const duplex = createWebSocketStream(ws, { highWaterMark: 65536 });
        this.metrics(stream.id); const value = this.counters.get(stream.id)!;
        bridge(stream.socket, duplex, ws, peer.bandwidth, this.budget,
          bytes => { value.sshBytesSToC += bytes; }, bytes => { value.sshBytesCToS += bytes; });
      });
    } catch { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); }
  };
  private acceptControl(ws: WebSocket) {
    ws.on('error', () => {});
    let peer: Peer | undefined, phase = 'hello', sessionId = '', generation = 0, hello: z.infer<typeof Hello> | undefined;
    const deadline = setTimeout(() => ws.terminate(), 30000);
    let queue: Promise<void> = Promise.resolve(), queuedBytes = 0, queuedMessages = 0;
    ws.on('message', (bytes, binary) => {
      const size = Buffer.byteLength(bytes.toString());
      if (queuedBytes + size > 65536 || queuedMessages >= 32) { ws.terminate(); return; }
      queuedBytes += size; queuedMessages++;
      queue = queue.then(async () => {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (binary) throw new Error('JSON required');
        const input = ControlMessage.parse(JSON.parse(bytes.toString()));
        if (input.epoch !== this.service.authority.identity.epoch) throw new Error('Epoch mismatch');
        if (phase === 'hello') {
          if (input.type !== 'hello' || input.generation !== 0) throw new Error('Hello required');
          sessionId = input.sessionId; hello = Hello.parse(input.payload);
          const session = this.service.sessions.get(sessionId);
          if (!session?.device || session.device.devicePublicKey !== hello.devicePublicKey) throw new Error('Device mismatch');
          const challenge = this.service.challenge(sessionId, 'control'); phase = 'auth';
          ws.send(JSON.stringify(message('challenge', input.epoch, sessionId, 0, { nonce: challenge.nonce, instanceId: challenge.instanceId }))); return;
        }
        if (input.sessionId !== sessionId) throw new Error('Session mismatch');
        if (phase === 'auth') {
          if (input.type !== 'auth' || input.generation !== 0) throw new Error('Auth required');
          const auth = z.object({ nonce: z.string(), signature: z.string() }).parse(input.payload);
          const result = await this.service.activate(sessionId, auth.nonce, hello, auth.signature);
          if (ws.readyState !== WebSocket.OPEN) return;
          generation = result.generation;
          const state = this.service.sessions.get(sessionId)!;
          if (state.generation !== generation || (this.peers.get(sessionId)?.generation ?? -1) > generation) { ws.close(1008, 'Stale generation'); return; }
          this.drop(sessionId);
          peer = { ws, id: sessionId, generation, last: Date.now(), verified: false, probing: false, bandwidth: new Bandwidth() };
          this.peers.set(sessionId, peer); phase = 'ready'; clearTimeout(deadline);
          if (result.revoked || state.authorization === 'revoked') { this.send(peer, 'revoke', {}); return; }
          this.send(peer, 'ready', { stage: 'transport' }); return;
        }
        if (!peer || this.peers.get(sessionId) !== peer || input.generation !== generation) throw new Error('Stale generation');
        peer.last = Date.now();
        if (this.service.summary(sessionId).authorization === 'revoked') { this.send(peer, 'revoke', {}); return; }
        if (input.type === 'pong') {
          const { timestamp } = z.object({ timestamp: z.number() }).parse(input.payload);
          const value = this.counters.get(sessionId); if (value && peer.ping === timestamp) { value.rttMs = Date.now() - timestamp; value.sampledAt = new Date().toISOString(); peer.ping = undefined; } return;
        }
        if (input.type === 'error') {
          const { streamId } = z.object({ streamId: z.string().optional() }).parse(input.payload);
          const stream = streamId ? this.streams.get(streamId) : undefined; if (stream?.id === sessionId) stream.socket.destroy(); return;
        }
        if (input.type !== 'ready' || z.object({ stage: z.literal('local') }).safeParse(input.payload).success !== true || peer.probing) throw new Error('Unexpected message');
        peer.probing = true;
        const current = peer;
        void this.connect(sessionId, true).then(async client => { await checkCapabilities(client, this.service.credentials(sessionId).device.home);
          if (this.peers.get(sessionId) === current && this.service.summary(sessionId).authorization === 'enrolled') { current.verified = true; current.verifiedAt = performance.now(); this.send(current, 'ready', { stage: 'verified' }); }
        }).catch(error => { this.service.emit('transport-error', error); if (this.peers.get(sessionId) === current) { this.send(current, 'error', { code: 'SSH_CAPABILITIES_FAILED' }); current.ws.close(1011); } });
      }).catch(() => ws.close(1008, 'Control rejected')).finally(() => { queuedBytes -= size; queuedMessages--; });
    });
    ws.once('close', () => { clearTimeout(deadline); if (peer && this.peers.get(sessionId) === peer) this.drop(sessionId); });
  }
  open(id: string, probe = false) {
    this.service.activeSummary(id);
    const peer = this.peers.get(id);
    if (!peer || (!probe && !peer.verified)) throw new DomainError('OFFLINE', 503);
    if ([...this.streams.values()].filter(value => value.id === id).length >= DEFAULTS.maxStreams) throw new DomainError('LIMIT_EXCEEDED', 429);
    const streamId = randomUUID(), ticket = token();
    return this.openPair(peer, streamId, ticket);
  }
  private openPair(peer: Peer, streamId: string, ticket: string): Duplex {
    const input = new PassThrough({ highWaterMark: 65536 }), output = new PassThrough({ highWaterMark: 65536 });
    const caller = Duplex.from({ readable: output, writable: input });
    const remote = Duplex.from({ readable: input, writable: output });
    const timer = setTimeout(() => remote.destroy(), 30000);
    const stream: Pending = { id: peer.id, generation: peer.generation, ticketHash: hash(ticket), until: Date.now() + 30000, socket: remote, timer };
    this.streams.set(streamId, stream);
    const cleanup = () => { clearTimeout(timer); this.streams.delete(streamId); stream.ws?.terminate(); caller.destroy(); remote.destroy(); input.destroy(); output.destroy(); };
    caller.on('error', () => {}); remote.on('error', () => {}); caller.once('close', cleanup); remote.once('close', cleanup);
    this.metrics(peer.id);
    this.send(peer, 'open', { streamId, ticket }); return caller;
  }
  async connect(id: string, probe = false) {
    const socket = this.open(id, probe);
    try {
      const client = await authenticated(this.service, id, socket), counters = this.counters.get(id)!;
      counters.sshConnectionsOpened++; counters.sshConnectionsActive++;
      client.once('close', () => { counters.sshConnectionsActive--; socket.destroy(); });
      return client;
    } catch (error) { socket.destroy(); throw error; }
  }
  private drop(id: string) {
    this.accountOnline(id);
    const peer = this.peers.get(id); this.peers.delete(id); peer?.ws.terminate();
    for (const stream of this.streams.values()) if (stream.id === id) stream.socket.destroy();
  }
  private revoke = (id: string) => {
    for (const stream of this.streams.values()) if (stream.id === id) stream.socket.destroy();
    this.accountOnline(id);
    const peer = this.peers.get(id); if (peer) { peer.verified = false; this.send(peer, 'revoke', {}); }
  };
  private accountOnline(id: string) {
    const peer = this.peers.get(id), value = this.counters.get(id);
    if (peer?.verified && peer.verifiedAt !== undefined && value) { const now = performance.now(); value.onlineSeconds += (now - peer.verifiedAt) / 1000; peer.verifiedAt = now; }
  }
  private freeze = () => { for (const id of [...this.peers.keys()]) this.drop(id); };
  close() {
    clearInterval(this.heartbeat); clearInterval(this.checkpoint); this.service.transport = undefined; this.service.off('revoke', this.revoke); this.service.authority.off('frozen', this.freeze); this.attached?.off('upgrade', this.upgrade);
    for (const id of [...this.peers.keys()]) this.drop(id);
    for (const ws of [...this.control.clients, ...this.data.clients]) ws.terminate();
    this.control.close(); this.data.close();
    return this.flush();
  }
}
