import type { IncomingMessage, Server } from 'node:http';
import type { Duplex } from 'node:stream';
import WebSocket, { WebSocketServer } from 'ws';
import { browserHash, browserKey } from './browser.js';
import type { RinkService } from './service.js';
type Viewer = { ws: WebSocket; id: string; browser: string };
export class BrowserEvents {
  private wss = new WebSocketServer({ noServer: true, maxPayload: 1024, perMessageDeflate: false });
  private viewers = new Set<Viewer>();
  private timer: NodeJS.Timeout;
  private server?: Server;
  private key: Buffer;
  constructor(readonly service: RinkService, master: Buffer) {
    this.key = browserKey(master);
    this.timer = setInterval(() => { for (const v of this.viewers) this.send(v); }, 2000);
    service.on('revoke', this.revoke);
  }
  attach(server: Server) { this.server = server; server.on('upgrade', this.upgrade); }
  private upgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    if (req.url !== '/api/v1/browser/events') return;
    socket.on('error', () => {});
    try {
      const origin = new URL(this.service.origin);
      if (req.headers.host !== origin.host || req.headers.origin !== origin.origin || req.headers['sec-websocket-protocol']) throw new Error('Rejected');
      const browser = browserHash(req, this.key), session = this.service.browserSession(browser);
      if (this.viewers.size >= 64 || [...this.viewers].filter(v => v.browser === browser).length >= 4) throw new Error('Limit');
      this.wss.handleUpgrade(req, socket, head, ws => {
        const viewer = { ws, id: session.id, browser }; this.viewers.add(viewer);
        ws.on('error', () => {}); ws.on('message', () => ws.close(1008, 'Read only')); ws.once('close', () => this.viewers.delete(viewer)); this.send(viewer);
      });
    } catch { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); }
  };
  private send(v: Viewer) {
    if (v.ws.readyState !== WebSocket.OPEN) return;
    try {
      const state = this.service.sessions.get(v.id);
      if (!state || state.browserHash !== v.browser || v.ws.bufferedAmount > 32768) { v.ws.terminate(); return; }
      const session = this.service.summary(v.id), metrics = this.service.transport?.metrics(v.id) ?? this.service.savedMetrics(v.id);
      v.ws.send(JSON.stringify({ session, metrics }));
    } catch { v.ws.close(1011, 'Status unavailable'); }
  }
  private revoke = (id: string) => { queueMicrotask(() => { for (const v of this.viewers) if (v.id === id) this.send(v); }); };
  close() { clearInterval(this.timer); this.server?.off('upgrade', this.upgrade); this.service.off('revoke', this.revoke); for (const v of this.viewers) v.ws.terminate(); this.wss.close(); }
}
