import { BLESSING, VERSION } from '@nyaarink/version';
import { parseArgs } from 'node:util';
import { randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, rm, stat } from 'node:fs/promises';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import WebSocket from 'ws';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const help = `NyaaRink ${VERSION} | ${BLESSING}
Environment: PUBLIC_BASE_URL (HTTPS), MCP_API_KEY (never a CLI argument).
invite create --helper <name> --purpose <text> [--request-id <uuid>]
invite cancel --invite <uuid>
session list | status | metrics | disconnect --session <uuid>
exec --session <uuid> --command <text> --shell posix|powershell|cmd [--cwd <C-path>] [--timeout <seconds>] [--wait] [--request-id <uuid>]
execution status | cancel --execution <uuid>
shell --session <uuid>
upload --session <uuid> --local <local-file> --remote <C-home-path>
download --session <uuid> --remote <C-home-path> --local <local-file>
ssh-config --session <uuid>
mcp stdio
SSH exit, Ctrl+C and network loss preserve authorization. Explicit session disconnect revokes access and stops current work.`;
async function main() {
  const { positionals: args, values: o } = parseArgs({ allowPositionals: true, options: {
    version: { type: 'boolean' }, help: { type: 'boolean' }, wait: { type: 'boolean' },
    session: { type: 'string' }, invite: { type: 'string' }, execution: { type: 'string' },
    helper: { type: 'string' }, purpose: { type: 'string' }, command: { type: 'string' }, shell: { type: 'string' }, cwd: { type: 'string' }, timeout: { type: 'string' },
    local: { type: 'string' }, remote: { type: 'string' }, 'request-id': { type: 'string' },
  } });
  if (o.version) { console.log(`NyaaRink ${VERSION} | ${BLESSING}`); return; }
  if (o.help || !args.length) { console.log(help); return; }
  const origin = new URL(process.env.PUBLIC_BASE_URL ?? '');
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('INVALID_PUBLIC_BASE_URL');
  const key = process.env.MCP_API_KEY; if (!key || key.length < 32) throw new Error('MISSING_MCP_API_KEY');
  const headers = { Authorization: 'Bearer ' + key };
  const required = (name: 'session' | 'invite' | 'execution' | 'local' | 'remote' | 'helper' | 'purpose' | 'command' | 'shell') => { const value = o[name]; if (!value) throw new Error('MISSING_' + name.toUpperCase()); return value; };
  const id = (name: 'session' | 'invite' | 'execution') => { const value = required(name); if (!/^[a-f0-9-]{36}$/i.test(value)) throw new Error('INVALID_ID'); return value; };
  const endpoint = (path: string) => new URL(path, origin);
  const checked = async (response: Response) => { if (!response.ok) { let code = 'HTTP_' + response.status; try { const body = await response.json() as { error?: { code?: string } }; if (/^[A-Z_]+$/.test(body.error?.code ?? '')) code = body.error!.code!; } catch { /* Never print arbitrary remote errors. */ } throw new Error(code); } return response; };
  const call = async (path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') => {
    const response = await fetch(endpoint(path), { method, headers: { ...headers, 'Content-Type': 'application/json', 'Idempotency-Key': o['request-id'] ?? randomUUID() }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    return (await checked(response)).json();
  };
  const output = (value: unknown) => console.log(JSON.stringify(value, null, 2));
  const [command, action] = args;
  if (command === 'mcp' && action === 'stdio') {
    const remote = new Client({ name: 'NyaaRink-bridge', version: VERSION });
    await remote.connect(new StreamableHTTPClientTransport(endpoint('/mcp'), { requestInit: { headers } }));
    const bridge = new Server({ name: 'NyaaRink', version: VERSION }, { capabilities: { tools: {} } });
    bridge.setRequestHandler(ListToolsRequestSchema, async () => { try { return await remote.listTools(); } catch { throw new Error('REMOTE_UNAVAILABLE'); } });
    bridge.setRequestHandler(CallToolRequestSchema, async (request, extra) => { try { return await remote.callTool(request.params, undefined, { signal: extra.signal }); } catch { throw new Error('REMOTE_UNAVAILABLE'); } });
    const transport = new StdioServerTransport();
    const close = () => { void bridge.close(); void remote.close(); };
    transport.onclose = close;
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, close);
    await bridge.connect(transport); return;
  }
  if (command === 'invite') {
    if (action === 'create') output(await call('/api/v1/invitations', { helperName: required('helper'), purpose: required('purpose') }));
    else if (action === 'cancel') output(await call(`/api/v1/invitations/${id('invite')}/cancel`, {})); else throw new Error('UNKNOWN_COMMAND');
  } else if (command === 'session') {
    if (action === 'list') output(await call('/api/v1/sessions'));
    else if (action === 'status') output(await call(`/api/v1/sessions/${id('session')}`));
    else if (action === 'metrics') output(await call(`/api/v1/sessions/${id('session')}/metrics`));
    else if (action === 'disconnect') output(await call(`/api/v1/sessions/${id('session')}/disconnect`, {})); else throw new Error('UNKNOWN_COMMAND');
  } else if (command === 'execution') {
    if (action === 'status') output(await call(`/api/v1/executions/${id('execution')}`));
    else if (action === 'cancel') output(await call(`/api/v1/executions/${id('execution')}/cancel`, {})); else throw new Error('UNKNOWN_COMMAND');
  } else if (command === 'exec') {
    let result = await call(`/api/v1/sessions/${id('session')}/executions`, { command: required('command'), shell: required('shell'), cwd: o.cwd, timeoutSeconds: o.timeout === undefined ? undefined : Number(o.timeout) }) as { executionId: string; state: string };
    if (o.wait) { console.error('executionId=' + result.executionId); while (['queued', 'running'].includes(result.state)) { await new Promise(ok => setTimeout(ok, 500)); result = await call(`/api/v1/executions/${result.executionId}`) as typeof result; } }
    output(result);
  } else if (command === 'ssh-config') output(await call(`/api/v1/sessions/${id('session')}/ssh-config`));
  else if (command === 'upload' || command === 'download') {
    const path = `/api/v1/sessions/${id('session')}/files?path=${encodeURIComponent(required('remote'))}`, local = required('local');
    if (command === 'upload') {
      const size = (await stat(local)).size; if (size > 100 * 1024 * 1024) throw new Error('LIMIT_EXCEEDED');
      const body = Readable.toWeb(createReadStream(local)) as ReadableStream;
      const response = await fetch(endpoint(path), { method: 'PUT', headers: { ...headers, 'Content-Type': 'application/octet-stream', 'Content-Length': String(size) }, body, duplex: 'half' } as RequestInit & { duplex: string });
      output(await (await checked(response)).json());
    } else {
      const response = await checked(await fetch(endpoint(path), { headers })); if (!response.body) throw new Error('EMPTY_RESPONSE');
      const temporary = local + '.nyaarink-' + randomUUID(); let bytes = 0;
      try {
        const limit = new Transform({ transform(chunk: Buffer, _encoding, done) { bytes += chunk.length; done(bytes > 100 * 1024 * 1024 ? new Error('LIMIT_EXCEEDED') : null, chunk); } });
        await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream), limit, createWriteStream(temporary, { flags: 'wx', mode: 0o600 }));
        await rename(temporary, local); output({ bytes });
      } finally { await rm(temporary, { force: true }); }
    }
  } else if (command === 'shell') {
    const ticket = await call(`/api/v1/sessions/${id('session')}/shells`, { cols: Math.min(500, process.stdout.columns ?? 80), rows: Math.min(300, process.stdout.rows ?? 24) }) as { shellId: string; ticket: string };
    const url = endpoint(`/api/v1/shells/${ticket.shellId}/stream`); url.protocol = 'wss:';
    await new Promise<void>((ok, fail) => {
      const ws = new WebSocket(url, { headers: { ...headers, 'X-NR-Ticket': ticket.ticket }, maxPayload: 65536, perMessageDeflate: false });
      let ready = false;
      const input = (data: Buffer) => { if (ready && ws.readyState === WebSocket.OPEN) { if (ws.bufferedAmount > 1024 * 1024) { ws.terminate(); return; } ws.send(data, { binary: true }); } };
      const resize = () => { if (ready && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols: Math.min(500, process.stdout.columns ?? 80), rows: Math.min(300, process.stdout.rows ?? 24) })); };
      const stop = () => ws.close();
      ws.on('message', (data, binary) => {
        if (binary) { const bytes = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data); if (!process.stdout.write(bytes)) { ws.pause(); process.stdout.once('drain', () => ws.resume()); } }
        else { const event = JSON.parse(data.toString()) as { type: string }; if (event.type === 'ready') { ready = true; process.stdin.setRawMode?.(true); process.stdin.resume(); } else if (event.type === 'error') console.error('SSH terminal unavailable'); }
      });
      process.stdin.on('data', input); process.stdin.once('end', stop); process.stdout.on('resize', resize); process.once('SIGTERM', stop);
      ws.once('error', () => fail(new Error('TERMINAL_CONNECTION_FAILED')));
      ws.once('close', () => { process.stdin.setRawMode?.(false); process.stdin.pause(); process.stdin.off('data', input); process.stdin.off('end', stop); process.stdout.off('resize', resize); process.off('SIGTERM', stop); ok(); });
    });
  } else throw new Error('UNKNOWN_COMMAND');
}
void main().catch(error => { console.error(error instanceof Error && /^[A-Z_0-9]+$/.test(error.message) ? error.message : 'NyaaRink request failed; check configuration and connectivity.'); process.exitCode = 1; });
