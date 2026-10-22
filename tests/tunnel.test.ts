import { afterEach, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server as HttpServer } from 'node:http';
import { Server, utils, type Connection } from 'ssh2';
import WebSocket from 'ws';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { TunnelHub } from '../apps/server/src/tunnel.js';
import { deviceMessage, deviceSign, hash, token } from '../apps/server/src/crypto.js';
import { deviceKeys, StateStore, type State } from '../apps/client/src/state.js';
import { runTunnel, type Connector } from '../apps/client/src/tunnel.js';
import { ControlMessage, message } from '../packages/contracts/tunnel.js';
import { Bandwidth, QueueBudget, meter } from '../packages/contracts/transport.js';
import { Readable } from 'node:stream';
import { sshFiles } from '../apps/server/src/proxy.js';
import { Operations, executionCommand } from '../apps/server/src/operations.js';
import { ExecInput } from '../packages/contracts/operations.js';
import { Shells } from '../apps/server/src/shells.js';

const cleanups: (() => Promise<unknown> | unknown)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
async function until(check: () => boolean, ms = 7000) { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('Condition timed out'); await new Promise(resolve => setTimeout(resolve, 20)); } }
async function setup(options: { revoked?: boolean; wrongHost?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'nyaarink-tunnel-')); cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const key = randomBytes(32), directory = join(root, 'authority'); Authority.initialize(directory, key);
  const service = await RinkService.open(new Authority(directory, key), join(root, 'db'), 'https://example.invalid:5116'); cleanups.push(() => service.close());
  const host = utils.generateKeyPairSync('ed25519'), pair = deviceKeys(), clients = new Set<Connection>();
  const ssh = new Server({ hostKeys: [host.private] }, client => {
    clients.add(client); client.on('error', () => {}); client.once('close', () => clients.delete(client));
    client.on('authentication', ctx => {
      const expected = utils.parseKey(service.credentials(sessionId).sshPublic);
      if (ctx.method === 'publickey' && !(expected instanceof Error) && !Array.isArray(expected) && expected.getPublicSSH().equals(ctx.key.data)) ctx.accept(); else ctx.reject();
    });
    client.on('session', accept => { const session = accept(); session.on('pty', accept => accept?.()); session.on('shell', accept => { const channel = accept(); channel.on('error', () => {}); channel.on('data', (data: Buffer) => channel.write(data)); });
      session.on('exec', (accept, _reject, info) => { const channel = accept(); channel.on('error', () => {});
        if (info.command.includes('NYAARINK_TEST_HANG')) return;
        channel.write(info.command.includes('NYAARINK_TEST_LARGE') ? Buffer.alloc(1100 * 1024, 65) : info.command === 'echo NyaaRink' ? 'NyaaRink\n' : 'result\n'); channel.exit(0); channel.end(); });
      session.on('sftp', accept => { const sftp = accept(); sftp.on('STAT', id => sftp.attrs(id, { mode: 0o40700, uid: 1, gid: 1, size: 0, atime: 0, mtime: 0 })); });
    });
    // With no tcpip listener ssh2 rejects with administratively prohibited.
    // Its explicit reject callback instead defaults to connect failed.
    client.on('request', (_accept, reject) => reject?.());
  });
  await new Promise<void>(resolve => ssh.listen(0, '127.0.0.1', resolve));
  cleanups.push(() => { for (const client of clients) client.end(); return new Promise<void>(resolve => ssh.close(() => resolve())); });
  const port = (ssh.address() as { port: number }).port;
  const invitation = await service.createInvitation({ helperName: 'Helper', purpose: 'isolated test' }, randomUUID()), browserHash = hash(token());
  const { id: sessionId } = await service.accept(invitation.inviteUrl.split('/').at(-1)!, browserHash, randomUUID());
  const boot = await service.bootstrap(browserHash, randomUUID());
  const bootstrap = { v: 1 as const, sessionId, enrollmentId: boot.enrollmentId!, bootstrapKey: boot.bootstrapKey!, expiresAt: boot.expiresAt!, origin: service.origin, instanceId: boot.instanceId!, epoch: boot.epoch! };
  const enrollment = { sessionId, enrollmentId: bootstrap.enrollmentId, devicePublicKey: pair.publicKey, account: 'ordinary', home: '/home/ordinary', shell: 'posix' as const, platform: 'linux' as const, host: '127.0.0.1' as const, port,
    hostKeys: [(utils.parseKey(host.public) as Exclude<ReturnType<typeof utils.parseKey>, Error | unknown[]>).getPublicSSH().toString('base64')] };
  await service.enroll(enrollment, bootstrap.bootstrapKey, deviceSign(pair.privateKey, deviceMessage('enroll', bootstrap.instanceId, bootstrap.epoch, sessionId, hash(bootstrap.bootstrapKey), enrollment)));
  if (options.wrongHost) service.sessions.get(sessionId)!.device!.hostKeys = [Buffer.from('wrong-host-key').toString('base64')];
  if (options.revoked) await service.disconnect(sessionId, 's_operator');
  const store = new StateStore(sessionId, join(root, 'client'));
  const state: State = { v: 1, bootstrap, devicePublicKey: pair.publicKey, devicePrivateKey: pair.privateKey, phase: 'ready', runtime: root, cleanup: 'pending', reported: false, releaseVersion: '0.1.0', enrollment };
  store.write(state);
  const server: HttpServer = createServer(); const hub = new TunnelHub(service); hub.attach(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  cleanups.push(async () => { await hub.close(); await new Promise<void>(resolve => server.close(() => resolve())); });
  const address = server.address() as { port: number };
  const sockets = new Set<WebSocket>(), tickets: { url: string; options: Parameters<Connector>[1] }[] = [];
  const connector: Connector = (url, options) => {
    if (url.includes('/streams/')) tickets.push({ url, options });
    const target = new URL(url); target.protocol = 'ws:'; target.host = '127.0.0.1:' + address.port;
    const socket = new WebSocket(target, { ...options, headers: { ...options.headers, Host: 'example.invalid:5116' } });
    sockets.add(socket); socket.once('close', () => sockets.delete(socket)); return socket;
  };
  const controller = new AbortController(); let revoked = false;
  const running = runTunnel(store, async () => { revoked = true; }, controller.signal, connector);
  cleanups.push(async () => { controller.abort(); for (const socket of sockets) socket.terminate(); await running; });
  return { service, hub, server, address, store, sessionId, connector, sockets, tickets, running, controller, isRevoked: () => revoked };
}
describe('outbound tunnel security and transport', () => {
  it('reserves concurrent execution capacity before persistence and permits idempotent replay at capacity', async () => {
    const { service, hub, sessionId } = await setup();
    let release!: () => void;
    const gate = new Promise<void>(ok => { release = ok; });
    const waitingHub = { service, operation() {}, connect: async () => { await gate; throw new Error('isolated unavailable transport'); } } as unknown as TunnelHub;
    const operations = new Operations(waitingHub);
    cleanups.push(async () => { release(); await operations.close(); });
    const ids = Array.from({ length: 35 }, () => randomUUID()), input = { command: 'never executed', shell: 'posix' };
    const results = await Promise.allSettled(ids.map(id => operations.start(sessionId, input, id)));
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(32);
    expect(results.filter(result => result.status === 'rejected').map(result => (result as PromiseRejectedResult).reason.message)).toEqual(Array(3).fill('LIMIT_EXCEEDED'));
    expect(service.executions.size).toBe(32);
    const index = results.findIndex(result => result.status === 'fulfilled');
    const first = (results[index] as PromiseFulfilledResult<ReturnType<Operations['get']>>).value;
    expect((await operations.start(sessionId, input, ids[index]!)).executionId).toBe(first.executionId);
    expect(hub.online(sessionId)).toBeTypeOf('boolean');
    release();
  }, 30000);
  it('opens a one-use PTY, resizes, closes without revocation and rejects ticket replay', async () => {
    const { hub, server, address, sessionId, service } = await setup(); await until(() => hub.online(sessionId));
    const shells = new Shells(hub, req => req.headers.authorization === 'Bearer test'); shells.attach(server); cleanups.push(() => shells.close());
    const ticket = shells.create(sessionId, { cols: 80, rows: 24 });
    const url = `ws://127.0.0.1:${address.port}/api/v1/shells/${ticket.shellId}/stream`;
    const options = { headers: { Host: 'example.invalid:5116', Authorization: 'Bearer test', 'X-NR-Ticket': ticket.ticket } };
    const ws = new WebSocket(url, options); cleanups.push(() => ws.terminate());
    ws.on('error', () => {});
    await new Promise<void>((ok, fail) => { ws.on('message', (data, binary) => { if (!binary && JSON.parse(data.toString()).type === 'ready') ok(); }); ws.once('error', fail); });
    ws.send(JSON.stringify({ type: 'resize', cols: 100, rows: 40 }));
    const echoed = new Promise<string>(ok => ws.once('message', data => ok(data.toString()))); ws.send(Buffer.from('hello'), { binary: true }); expect(await echoed).toBe('hello');
    const replay = new WebSocket(url, options); replay.on('error', () => {});
    const rejected = await new Promise<number>(ok => replay.once('unexpected-response', (_req, res) => { ok(res.statusCode!); res.resume(); replay.terminate(); })); expect(rejected).toBe(403);
    ws.send(JSON.stringify({ type: 'close' })); await new Promise(ok => ws.once('close', ok));
    expect(service.summary(sessionId).authorization).toBe('enrolled');
  }, 15000);
  it('executes once per durable request and limits output without revoking on cancel', async () => {
    const { service, hub, sessionId } = await setup(); await until(() => hub.online(sessionId));
    const operations = new Operations(hub); cleanups.push(() => operations.close());
    const requestId = randomUUID(), input = { command: 'test', shell: 'posix' };
    const task = await operations.start(sessionId, input, requestId);
    await until(() => operations.get(task.executionId).state === 'succeeded');
    expect(operations.get(task.executionId).stdout).toBe('result\n');
    expect((await operations.start(sessionId, input, requestId)).executionId).toBe(task.executionId);
    expect(service.executions.size).toBe(1);
    await expect(operations.start(sessionId, { ...input, command: 'different' }, requestId)).rejects.toThrow('CONFLICT');
    const large = await operations.start(sessionId, { ...input, command: 'NYAARINK_TEST_LARGE' }, randomUUID());
    await until(() => operations.get(large.executionId).state === 'succeeded');
    expect(operations.get(large.executionId).truncated).toBe(true);
    expect(Buffer.byteLength(operations.get(large.executionId).stdout)).toBe(1024 * 1024);
    const hanging = await operations.start(sessionId, { ...input, command: 'NYAARINK_TEST_HANG' }, randomUUID());
    await until(() => operations.get(hanging.executionId).state === 'running');
    expect(operations.cancel(hanging.executionId).state).toBe('cancelled');
    expect(service.summary(sessionId).authorization).toBe('enrolled');
    await service.disconnect(sessionId, 's_operator');
  }, 20000);
  it('uses explicit platform shells and quotes cwd without interpreting it as code', () => {
    const input = ExecInput.parse({ command: 'echo ok', shell: 'posix', cwd: "/tmp/a';echo injected" });
    expect(executionCommand(input, 'linux')).toContain("'\\''");
    expect(() => executionCommand(input, 'win32')).toThrow('INVALID_REQUEST');
    expect(() => executionCommand({ ...input, shell: 'cmd', cwd: 'C:\\a&evil' }, 'win32')).toThrow('INVALID_REQUEST');
    const ps = executionCommand({ ...input, shell: 'powershell' }, 'win32');
    expect(Buffer.from(ps.split(' ').at(-1)!, 'base64').toString('utf16le')).toContain("-LiteralPath '/tmp/a'';echo injected'");
  });
  it('enforces strict envelopes, including payload types and no arbitrary target', () => {
    const input = message('open', randomUUID(), randomUUID(), 1, { streamId: randomUUID(), ticket: token() });
    expect(ControlMessage.safeParse(input).success).toBe(true);
    expect(ControlMessage.safeParse({ ...input, payload: { ...input.payload as object, host: '10.0.0.1' } }).success).toBe(false);
    expect(ControlMessage.safeParse({ ...input, v: 2 }).success).toBe(false);
  });
  it('keeps bandwidth and global queued bytes bounded and releases reservation on destroy', async () => {
    const bandwidth = new Bandwidth(1024), budget = new QueueBudget(4096), stream = meter(bandwidth, budget);
    Readable.from([Buffer.alloc(2048)]).pipe(stream); stream.resume();
    await until(() => budget.bytes > 0); stream.destroy();
    expect(budget.bytes).toBe(0); expect(() => budget.reserve(4097)).toThrow();
  });
  it('renders pinned OpenSSH configuration without accepting configuration injection', () => {
    const id = randomUUID(), key = utils.generateKeyPairSync('ed25519');
    const parsed = utils.parseKey(key.public);
    if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('Invalid fixture');
    const files = sshFiles(id, 'ordinary', [parsed.getPublicSSH().toString('base64')], '/run/nyaarink/' + id, '/app/proxy.js');
    expect(files.config).toContain('StrictHostKeyChecking yes');
    expect(files.known).toContain(`nr-${id} ssh-ed25519 `);
    expect(() => sshFiles(id, 'user\nProxyCommand evil', [], '/run/nr', '/app/proxy.js')).toThrow();
  });
  it('cleans an enrollment revoked before its first control connection', async () => {
    const fixture = await setup({ revoked: true });
    await until(fixture.isRevoked); await fixture.running;
    expect(fixture.service.sessions.get(fixture.sessionId)!.generation).toBe(0);
    expect(fixture.hub.online(fixture.sessionId)).toBe(false);
  });
  it('never marks a changed SSH host key online', async () => {
    const fixture = await setup({ wrongHost: true });
    await until(() => fixture.tickets.length > 0);
    await new Promise(resolve => setTimeout(resolve, 200));
    expect(fixture.hub.online(fixture.sessionId)).toBe(false);
    expect(fixture.service.summary(fixture.sessionId).authorization).toBe('enrolled');
  });
  it('authenticates SSH through outbound WSS, probes capabilities, reconnects without revoking, then closes on explicit revoke', async () => {
    const { service, hub, sessionId, sockets, running, isRevoked, tickets, connector } = await setup();
    await until(() => hub.online(sessionId));
    const consumed = tickets[0]!;
    const replay = connector(consumed.url, consumed.options);
    const status = await new Promise<number>(resolve => { replay.on('unexpected-response', (_req, res) => { resolve(res.statusCode!); res.resume(); replay.terminate(); }); replay.on('error', () => {}); });
    expect(status).toBe(403);
    const client = await hub.connect(sessionId);
    const output = await new Promise<string>((resolve, reject) => client.exec('test', (error, channel) => { if (error) { reject(error); return; } let text = ''; channel.on('data', (data: Buffer) => text += data); channel.on('close', () => resolve(text)); }));
    expect(output).toBe('result\n'); client.end();
    const previous = service.sessions.get(sessionId)!.generation;
    for (const socket of sockets) socket.terminate();
    await until(() => service.sessions.get(sessionId)!.generation > previous && hub.online(sessionId));
    expect(service.summary(sessionId).authorization).toBe('enrolled');
    const active = await hub.connect(sessionId); let closed = false; active.once('close', () => closed = true);
    await service.disconnect(sessionId, 's_operator'); await until(() => closed && isRevoked()); await running;
    expect(hub.online(sessionId)).toBe(false); expect(() => hub.open(sessionId)).toThrow('REVOKED');
    expect(hub.metrics(sessionId).sshBytesSToC).toBeGreaterThan(0);
  }, 20000);
  it('closes active streams on authority freeze without revoking authorization', async () => {
    const { service, hub, sessionId } = await setup(); await until(() => hub.online(sessionId));
    const client = await hub.connect(sessionId); let closed = false; client.on('close', () => closed = true);
    service.authority.freeze('TEST');
    expect(() => hub.open(sessionId)).toThrow('FROZEN');
    await until(() => closed, 17000);
    expect(service.summary(sessionId).authorization).toBe('enrolled');
  }, 22000);
});
