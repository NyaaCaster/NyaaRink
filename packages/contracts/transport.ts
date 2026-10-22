import { Transform, type Duplex } from 'node:stream';
import type WebSocket from 'ws';

export const DATA_LIMIT = 256 * 1024, CHUNK = 64 * 1024, QUEUE_LIMIT = 1024 * 1024;
export class QueueBudget {
  bytes = 0;
  constructor(readonly limit = 128 * 1024 * 1024) {}
  reserve(bytes: number) { if (this.bytes + bytes > this.limit) throw new Error('Global stream queue exceeded'); this.bytes += bytes; }
  release(bytes: number) { this.bytes -= bytes; }
}
export class Bandwidth {
  private tokens: number;
  private at = performance.now();
  constructor(readonly rate = 10 * 1024 * 1024) { this.tokens = rate; }
  delay(bytes: number) {
    const now = performance.now();
    this.tokens = Math.min(this.rate, this.tokens + (now - this.at) * this.rate / 1000) - bytes;
    this.at = now;
    return Math.max(0, -this.tokens * 1000 / this.rate);
  }
}
export function meter(bandwidth: Bandwidth, budget: QueueBudget, count: (bytes: number) => void = () => {}) {
  let held = 0, timer: NodeJS.Timeout | undefined;
  return new Transform({ highWaterMark: CHUNK,
    transform(chunk: Buffer, _encoding, done) {
      if (chunk.length > QUEUE_LIMIT) { done(new Error('Stream queue exceeded')); return; }
      try { budget.reserve(chunk.length); held = chunk.length; } catch (error) { done(error as Error); return; }
      timer = setTimeout(() => {
        timer = undefined;
        for (let at = 0; at < chunk.length; at += CHUNK) this.push(chunk.subarray(at, at + CHUNK));
        count(chunk.length); budget.release(held); held = 0; done();
      }, bandwidth.delay(chunk.length));
    },
    destroy(error, done) { if (timer) clearTimeout(timer); budget.release(held); held = 0; done(error); },
  });
}
export function bridge(a: Duplex, b: Duplex, ws: WebSocket, bandwidth: Bandwidth, budget: QueueBudget,
  sent: (bytes: number) => void = () => {}, received: (bytes: number) => void = () => {}) {
  // Reserve the complete flow allowance, including a frame crossing the high
  // water mark. Reserving only the transforming chunk misses readable/WS queues.
  const allowance = 2 * QUEUE_LIMIT;
  try { budget.reserve(allowance); } catch { a.destroy(); b.destroy(); ws.terminate(); return () => {}; }
  const local = new QueueBudget(allowance);
  const outgoing = meter(bandwidth, local, sent), incoming = meter(bandwidth, local, received);
  let closed = false;
  const stop = () => { if (closed) return; closed = true; clearInterval(watch); budget.release(allowance); a.destroy(); b.destroy(); outgoing.destroy(); incoming.destroy(); ws.terminate(); };
  const check = () => {
    if (ws.bufferedAmount + a.writableLength + b.writableLength + a.readableLength + b.readableLength + outgoing.readableLength + incoming.readableLength + outgoing.writableLength + incoming.writableLength > QUEUE_LIMIT) stop();
  };
  const watch = setInterval(check, 100);
  for (const stream of [a, b, outgoing, incoming]) stream.on('data', check);
  for (const stream of [a, b, outgoing, incoming]) { stream.on('error', stop); stream.on('close', stop); }
  ws.on('error', stop); ws.on('close', stop);
  a.pipe(outgoing).pipe(b); b.pipe(incoming).pipe(a);
  return stop;
}
