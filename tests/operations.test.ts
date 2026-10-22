import { afterEach, describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, createReadStream, createWriteStream, lstat, rename, unlink } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import type { SFTPWrapper, Client as SSHClient } from 'ssh2';
import { Files, filePath } from '../apps/server/src/files.js';
import type { TunnelHub } from '../apps/server/src/tunnel.js';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { createApp } from '../apps/server/src/app.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { request } from 'node:http';

// Node fetch deliberately ignores an overridden Host. Use HTTP directly for
// tests of the public authority behind a loopback socket.
const httpFetch: typeof fetch = async (input, init) => {
  const req = new Request(input, init), body = Buffer.from(await req.arrayBuffer());
  return new Promise((ok, fail) => {
    const outgoing = request(new URL(req.url), { method: req.method, headers: Object.fromEntries(req.headers) }, res => {
      const chunks: Buffer[] = []; res.on('data', c => chunks.push(c)); res.on('end', () => ok(new Response(Buffer.concat(chunks), { status: res.statusCode!, headers: res.headers as Record<string, string> })));
    }); outgoing.on('error', fail); outgoing.end(body);
  });
};

const cleanup: (() => unknown | Promise<unknown>)[] = [];
afterEach(async () => { for (const fn of cleanup.splice(0).reverse()) await fn(); });
function temporary() { const path = mkdtempSync(join(tmpdir(), 'nyaarink-operations-')); cleanup.push(() => rmSync(path, { recursive: true, force: true })); return path; }
describe('bounded SFTP files', () => {
  function fixture() {
    const directory = temporary(), root = '/home/ordinary';
    const local = (path: string) => join(directory, path.slice(root.length));
    const sftp = Object.assign(new EventEmitter(), {
      realpath: (_path: string, callback: (error: null, path: string) => void) => callback(null, root),
      lstat: (path: string, callback: (error: unknown, stat?: unknown) => void) => {
        if (path.endsWith('/link')) { callback(null, { isSymbolicLink: () => true }); return; }
        lstat(local(path), (error, stat) => callback(error ? { code: error.code === 'ENOENT' ? 2 : 4 } : null, stat));
      },
      createWriteStream: (path: string, options: object) => createWriteStream(local(path), options),
      createReadStream: (path: string) => createReadStream(local(path)),
      ext_openssh_rename: (from: string, to: string, callback: (error: unknown) => void) => rename(local(from), local(to), callback),
      unlink: (path: string, callback: (error: unknown) => void) => unlink(local(path), callback), end() {},
    }) as unknown as SFTPWrapper;
    const client = Object.assign(new EventEmitter(), { sftp: (callback: (error: null, result: SFTPWrapper) => void) => callback(null, sftp), destroy() {} }) as unknown as SSHClient;
    const hub = { service: { credentials: () => ({ device: { home: root } }), activeSummary() {} }, connect: async () => client, operation() {} } as unknown as TunnelHub;
    return { directory, files: new Files(hub) };
  }
  it('rejects traversal, other roots, drive syntax and symlinks', async () => {
    const { files } = fixture();
    for (const path of ['../secret', '/etc/passwd', 'x\\y', 'C:/secret', 'a/../b', 'bad\0']) expect(() => filePath('/home/ordinary', path)).toThrow('INVALID_REQUEST');
    await expect(files.transfer('id', 'link', 'download', new Writable({ write(_c, _e, done) { done(); } }))).rejects.toThrow('INVALID_REQUEST');
  });
  it('atomically replaces files, roundtrips bytes and removes partial uploads', async () => {
    const { directory, files } = fixture(); writeFileSync(join(directory, 'file'), 'old');
    await expect(files.transfer('id', 'file', 'upload', Readable.from([Buffer.from('new')]), 3)).resolves.toEqual({ bytes: 3 });
    const parts: Buffer[] = [];
    await files.transfer('id', 'file', 'download', new Writable({ write(chunk: Buffer, _e, done) { parts.push(chunk); done(); } }), 3);
    expect(Buffer.concat(parts).toString()).toBe('new');
    await expect(files.transfer('id', 'file', 'upload', Readable.from([Buffer.from('too long')]), 3)).rejects.toThrow('LIMIT_EXCEEDED');
    expect(readFileSync(join(directory, 'file'), 'utf8')).toBe('new');
    expect(readdirSync(directory)).toEqual(['file']);
    await expect(files.transfer('id', 'file', 'download', new Writable({ write(_c, _e, done) { done(); } }), 2)).rejects.toThrow('LIMIT_EXCEEDED');
  });
});
describe('stateless MCP HTTP', () => {
  it('discovers and calls tools through the real SDK, enforces bearer/host/origin and body limits', async () => {
    const root = temporary(), key = randomBytes(32), api = randomBytes(32).toString('hex');
    Authority.initialize(join(root, 'authority'), key);
    const service = await RinkService.open(new Authority(join(root, 'authority'), key), join(root, 'state'), 'https://example.invalid:5116'); cleanup.push(() => service.close());
    const app = createApp(service, { PUBLIC_BASE_URL: service.origin, MCP_API_KEY: api, MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey: key });
    const server = app.listen(0, '127.0.0.1'); await new Promise<void>(ok => server.once('listening', ok)); cleanup.push(() => new Promise<void>(ok => server.close(() => ok())));
    const base = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
    const h = { Host: 'example.invalid:5116', Authorization: 'Bearer ' + api, 'Content-Type': 'application/json' };
    expect((await httpFetch(base + '/mcp', { method: 'POST', headers: { Host: h.Host }, body: '{}' })).status).toBe(401);
    expect((await httpFetch(base + '/mcp', { method: 'POST', headers: { ...h, Origin: 'https://evil.invalid' }, body: '{}' })).status).toBe(403);
    expect((await httpFetch(base + '/mcp', { method: 'POST', headers: { ...h, Host: 'evil.invalid' }, body: '{}' })).status).toBe(403);
    expect((await httpFetch(base + '/mcp', { headers: h })).status).toBe(405);
    expect((await httpFetch(base + '/api/v1/invitations', { method: 'POST', headers: h, body: JSON.stringify({ huge: 'x'.repeat(33000) }) })).status).toBe(413);
    const client = new Client({ name: 'NyaaRink-integration', version: '1.0.0' }); cleanup.push(() => client.close());
    await client.connect(new StreamableHTTPClientTransport(new URL(base + '/mcp'), { fetch: httpFetch, requestInit: { headers: h } }));
    const tools = await client.listTools(); expect(tools.tools.map(t => t.name)).toContain('rink_disconnect');
    const requestId = randomUUID(), args = { helperName: 'Helper', purpose: 'Test', requestId };
    const result = await client.callTool({ name: 'rink_create_invitation', arguments: args }); expect(result.isError).not.toBe(true);
    const again = await client.callTool({ name: 'rink_create_invitation', arguments: args }); expect(again.isError).not.toBe(true); expect(service.invitations.size).toBe(1);
    const invalid = await client.callTool({ name: 'rink_create_invitation', arguments: { ...args, purpose: 'Other' } }); expect(invalid.isError).toBe(true);
    expect(JSON.stringify(invalid)).not.toContain(api);
    expect((await client.callTool({ name: 'rink_list_sessions', arguments: {} })).isError).not.toBe(true);
  });
});
