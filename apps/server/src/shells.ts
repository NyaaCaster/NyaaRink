import { randomUUID } from 'node:crypto';
import type { Server, IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import type { Client, ClientChannel } from 'ssh2';
import WebSocket, { WebSocketServer } from 'ws';
import { z } from 'zod';
import { DomainError } from '@nyaarink/contracts';
import { hash, token } from './crypto.js';
import type { TunnelHub } from './tunnel.js';

export const TerminalSize = z.object({ cols: z.number().int().min(1).max(500).default(80), rows: z.number().int().min(1).max(300).default(24) }).strict();
type Ticket = { sessionId: string; digest: string; until: number; cols: number; rows: number };
type Active = { sessionId: string; ws: WebSocket; client?: Client; channel?: ClientChannel };
export class Shells {
  private wss = new WebSocketServer({ noServer: true, maxPayload: 65536, perMessageDeflate: false });
  private tickets = new Map<string, Ticket>();
  private active = new Set<Active>();
  private server?: Server;
  private timer: NodeJS.Timeout;
  constructor(readonly hub: TunnelHub, private authorize: (req: IncomingMessage) => boolean) {
    hub.service.on('revoke', this.revoke);
    this.timer = setInterval(() => this.prune(), 1000);
  }
  private prune() { for (const [id, t] of this.tickets) if (t.until <= Date.now()) this.tickets.delete(id); }
  create(sessionId: string, raw: unknown) {
    this.hub.service.credentials(sessionId); const size = TerminalSize.parse(raw); this.prune();
    if (this.tickets.size + this.active.size >= 32) throw new DomainError('LIMIT_EXCEEDED', 429);
    const shellId = randomUUID(), ticket = token(), until = Date.now() + 30000;
    this.tickets.set(shellId, { sessionId, digest: hash(ticket), until, ...size });
    return { shellId, ticket, expiresAt: new Date(until).toISOString() };
  }
  attach(server: Server) { this.server = server; server.on('upgrade', this.upgrade); }
  private upgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    if (!req.url?.startsWith('/api/v1/shells/')) return;
    socket.on('error', () => {});
    try {
      const match = /^\/api\/v1\/shells\/([a-f0-9-]{36})\/stream$/.exec(req.url);
      const origin = new URL(this.hub.service.origin);
      if (!match || !this.authorize(req) || req.headers.host !== origin.host || (req.headers.origin && req.headers.origin !== origin.origin) || req.headers['sec-websocket-protocol']) throw new Error('Rejected');
      const t = this.tickets.get(match[1]!);
      const credential = req.headers['x-nr-ticket'];
      if (!t || t.until <= Date.now() || typeof credential !== 'string' || hash(credential) !== t.digest) throw new Error('Rejected');
      this.hub.service.credentials(t.sessionId);
      this.tickets.delete(match[1]!);
      this.wss.handleUpgrade(req, socket, head, ws => { void this.run(ws, t); });
    } catch { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); }
  };
  private async run(ws: WebSocket, ticket: Ticket) {
    const active: Active = { sessionId: ticket.sessionId, ws }; this.active.add(active);
    ws.on('error', () => {});
    let pending = 0, closed = false;
    const poll = setInterval(() => {
      if (ws.bufferedAmount > 1024 * 1024) ws.terminate();
      else if (ws.bufferedAmount < 65536) { active.channel?.resume(); active.channel?.stderr.resume(); }
    }, 50);
    const close = () => { if (closed) return; closed = true; clearInterval(poll); active.channel?.destroy(); active.client?.destroy(); this.active.delete(active); ws.close(); };
    ws.once('close', close);
    try {
      const client = await this.hub.connect(ticket.sessionId); active.client = client;
      if (closed) { client.destroy(); return; }
      client.once('close', close); this.hub.operation(ticket.sessionId);
      const channel = await new Promise<ClientChannel>((ok, fail) => client.shell({ term: 'xterm-256color', cols: ticket.cols, rows: ticket.rows }, (error, stream) => error ? fail(error) : ok(stream)));
      if (closed) { channel.destroy(); return; } active.channel = channel;
      channel.on('error', close);
      const output = (bytes: Buffer) => {
        if (ws.readyState !== WebSocket.OPEN) return;
        ws.send(bytes, { binary: true }, error => { if (error) close(); });
        if (ws.bufferedAmount > 65536) { channel.pause(); channel.stderr.pause(); }
      };
      channel.on('data', output); channel.stderr.on('data', output);
      channel.once('close', (code?: number) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'exit', code: code ?? null })); close(); });
      ws.on('message', (bytes, binary) => {
        try {
          if (binary) {
            const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes as ArrayBuffer);
            pending += data.length; if (pending > 1024 * 1024) throw new Error('Input limit');
            const writable = channel.write(data, () => { pending -= data.length; });
            if (!writable) ws.pause();
          } else {
            const input = z.discriminatedUnion('type', [TerminalSize.extend({ type: z.literal('resize') }).strict(), z.object({ type: z.literal('close') }).strict()]).parse(JSON.parse(bytes.toString()));
            if (input.type === 'close') close(); else channel.setWindow(input.rows, input.cols, 0, 0);
          }
        } catch { ws.close(1008, 'Terminal input rejected'); close(); }
      });
      channel.on('drain', () => ws.resume());
      ws.send(JSON.stringify({ type: 'ready' }));
    } catch { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'error', code: 'OFFLINE' })); close(); }
  }
  private revoke = (id: string) => {
    for (const [key, ticket] of this.tickets) if (ticket.sessionId === id) this.tickets.delete(key);
    for (const a of this.active) if (a.sessionId === id) { a.ws.terminate(); a.channel?.destroy(); a.client?.destroy(); }
  };
  close() { clearInterval(this.timer); this.server?.off('upgrade', this.upgrade); this.hub.service.off('revoke', this.revoke); this.tickets.clear(); for (const a of this.active) { a.ws.terminate(); a.client?.destroy(); } this.wss.close(); }
}
