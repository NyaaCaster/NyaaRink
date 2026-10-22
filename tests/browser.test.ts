import { afterEach, expect, it } from 'vitest';
import { chromium, expect as browserExpect } from '@playwright/test';
import { createServer } from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import WebSocket from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { BrowserEvents } from '../apps/server/src/events.js';
import { createApp } from '../apps/server/src/app.js';
import type { Artifacts } from '../apps/server/src/artifacts.js';

const cleanup: (() => unknown | Promise<unknown>)[] = [];
afterEach(async () => { for (const fn of cleanup.splice(0).reverse()) await fn(); });
async function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'nyaarink-browser-')); cleanup.push(() => rmSync(root, { recursive: true, force: true }));
  const cert = join(root, 'test.crt'), privateKey = join(root, 'test.key');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', privateKey, '-out', cert, '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'pipe', windowsHide: true, timeout: 30000 });
  const server = createServer({ key: readFileSync(privateKey), cert: readFileSync(cert) });
  await new Promise<void>(ok => server.listen(0, '127.0.0.1', ok));
  const origin = 'https://127.0.0.1:' + (server.address() as { port: number }).port;
  const masterKey = randomBytes(32), api = randomBytes(32).toString('hex'); Authority.initialize(join(root, 'authority'), masterKey);
  const service = await RinkService.open(new Authority(join(root, 'authority'), masterKey), join(root, 'state'), origin); cleanup.push(() => service.close());
  const artifacts = { get: (platform: 'win32' | 'linux') => ({ platform, arch: 'x64', version: '0.1.0', filename: `nyaarink-client-0.1.0-${platform}-x64.${platform === 'win32' ? 'zip' : 'tar.gz'}`, sha256: '0'.repeat(64), manifestSha256: '0'.repeat(64) }) } as Artifacts;
  server.on('request', createApp(service, { PUBLIC_BASE_URL: origin, MCP_API_KEY: api, MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey }, artifacts));
  cleanup.push(() => { server.closeAllConnections(); return new Promise<void>(ok => server.close(() => ok())); });
  const events = new BrowserEvents(service, masterKey); events.attach(server); cleanup.push(() => events.close());
  return { service, origin, api, cert };
}
async function browser() {
  // Explicit override supports an already installed browser without downloading
  // or silently changing the developer's browser installation.
  const installed = process.env.NYAARINK_TEST_CHROMIUM;
  if (installed && !existsSync(installed)) throw new Error('NYAARINK_TEST_CHROMIUM does not exist');
  const instance = await chromium.launch({ headless: true, executablePath: installed }); cleanup.push(() => instance.close()); return instance;
}
it('runs the real invitation UI, themes, script download, C revocation and invalid refresh', async () => {
  const { service } = await fixture(), instance = await browser();
  // The ephemeral local test certificate is intentionally trusted only in this
  // browser context. Production TLS validation is unchanged.
  const context = await instance.newContext({ ignoreHTTPSErrors: true, colorScheme: 'dark', viewport: { width: 390, height: 844 } });
  const page = await context.newPage(), errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  const invite = await service.createInvitation({ helperName: '<img src=x onerror=alert(1)>', purpose: 'Browser integration' }, randomUUID());
  await page.goto(invite.inviteUrl);
  await browserExpect(page.getByRole('heading', { name: '为这台电脑，开启一次远程协助。' })).toBeVisible();
  expect(service.sessions.size).toBe(0);
  await browserExpect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  if (process.env.NYAARINK_TEST_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.NYAARINK_TEST_SCREENSHOT_DIR, 'invitation-dark.png'), fullPage: true });
  await page.emulateMedia({ colorScheme: 'light' }); await browserExpect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  if (process.env.NYAARINK_TEST_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.NYAARINK_TEST_SCREENSHOT_DIR, 'invitation-light.png'), fullPage: true });
  await page.getByRole('button', { name: '暗色', exact: true }).click(); await page.reload();
  await browserExpect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await browserExpect(page.getByRole('button', { name: '接受访问', exact: true })).toBeDisabled();
  await page.getByRole('checkbox').check(); await page.getByRole('button', { name: '接受访问', exact: true }).click();
  await browserExpect(page.getByRole('button', { name: '断开连接', exact: true })).toBeVisible(); expect(service.sessions.size).toBe(1);
  await page.getByRole('button', { name: 'Windows', exact: true }).click();
  const downloaded = page.waitForEvent('download'); await page.getByRole('button', { name: '下载连接脚本', exact: true }).click();
  const download = await downloaded; expect(download.suggestedFilename()).toMatch(/^NyaaRink-.*\.bat$/); await download.delete();
  const stranger = await instance.newContext({ ignoreHTTPSErrors: true }); const other = await stranger.newPage(); await other.goto(invite.inviteUrl);
  await browserExpect(other.getByRole('heading', { name: '此链接没有有效邀请。' })).toBeVisible(); await stranger.close();
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
  await browserExpect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: '确认断开连接', exact: true }).focus(); await page.keyboard.press('Enter');
  await browserExpect(page.getByRole('heading', { name: '访问权限已撤销' })).toBeVisible();
  await browserExpect(page.getByText('请删除下载的本次连接脚本。', { exact: true })).toBeVisible();
  await page.reload(); await browserExpect(page.getByRole('heading', { name: '此链接没有有效邀请。' })).toBeVisible();
  expect(errors).toEqual([]); await context.close();
}, 60000);

it('shows S revocation over authenticated events, rejects cross-origin/forged cookies and preserves authorization on socket loss', async () => {
  const { service, origin } = await fixture(), instance = await browser();
  const context = await instance.newContext({ ignoreHTTPSErrors: true }); const page = await context.newPage();
  const invite = await service.createInvitation({ helperName: 'Helper', purpose: 'Server revocation' }, randomUUID());
  await page.goto(invite.inviteUrl); await page.getByRole('checkbox').check(); await page.getByRole('button', { name: '接受访问', exact: true }).click();
  await browserExpect(page.getByRole('button', { name: '断开连接', exact: true })).toBeVisible();
  const cookie = (await context.cookies()).map(c => c.name + '=' + c.value).join('; '), id = [...service.sessions.keys()][0]!;
  for (const headers of [{ Origin: 'https://evil.invalid', Cookie: cookie }, { Origin: origin, Cookie: '__Host-nr=forged' }, { Cookie: cookie }]) {
    const ws = new WebSocket(origin.replace('https:', 'wss:') + '/api/v1/browser/events', { rejectUnauthorized: false, headers }); ws.on('error', () => {});
    const status = await new Promise<number>(ok => ws.once('unexpected-response', (_req, res) => { res.resume(); ok(res.statusCode!); ws.terminate(); })); expect(status).toBe(403);
  }
  await context.setOffline(true); expect(service.summary(id).authorization).toBe('accepted'); await context.setOffline(false);
  await service.disconnect(id, 's_operator');
  await browserExpect(page.getByRole('heading', { name: '访问权限已撤销' })).toBeVisible({ timeout: 10000 });
  await browserExpect(page.getByText('已确认清理', { exact: true })).toBeVisible();
  await page.reload(); await browserExpect(page.getByRole('heading', { name: '此链接没有有效邀请。' })).toBeVisible(); await context.close();
}, 60000);

it('uses HTTPS CLI and the real stdio bridge with a local CA, keeping protocol output free of credentials', async () => {
  const { origin, api, cert, service } = await fixture();
  const env = { ...process.env, PUBLIC_BASE_URL: origin, MCP_API_KEY: api, NODE_EXTRA_CA_CERTS: cert };
  const run = (...args: string[]) => new Promise<{ code: number | null; out: string; error: string }>((ok, fail) => {
    const child = spawn(process.execPath, ['dist/cli/index.js', ...args], { env, windowsHide: true }); let out = '', error = '';
    child.stdout.on('data', bytes => { out += bytes; }); child.stderr.on('data', bytes => { error += bytes; }); child.on('error', fail); child.once('exit', code => ok({ code, out, error }));
  });
  const created = await run('invite', 'create', '--helper', 'CLI', '--purpose', 'Test'); expect(created.code).toBe(0); expect(created.out).not.toContain(api);
  expect(JSON.parse(created.out).inviteUrl).toMatch(/^https:/); expect(service.invitations.size).toBe(1);
  const client = new Client({ name: 'NyaaRink-stdio-test', version: '1.0.0' });
  const stringEnv = Object.fromEntries(Object.entries(env).filter((entry): entry is [string, string] => typeof entry[1] === 'string'));
  const transport = new StdioClientTransport({ command: process.execPath, args: ['dist/cli/index.js', 'mcp', 'stdio'], env: stringEnv, stderr: 'pipe' });
  cleanup.push(() => client.close()); await client.connect(transport);
  expect((await client.listTools()).tools.map(tool => tool.name)).toContain('rink_disconnect');
  const result = await client.callTool({ name: 'rink_list_sessions', arguments: {} }); expect(result.isError).not.toBe(true); expect(JSON.stringify(result)).not.toContain(api);
  await client.close();
}, 30000);
