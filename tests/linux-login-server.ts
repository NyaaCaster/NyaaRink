// Opt-in fixture for a disposable Linux account. Never starts a model or container.
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { createApp } from '../apps/server/src/app.js';
import { TunnelHub } from '../apps/server/src/tunnel.js';
import { Operations } from '../apps/server/src/operations.js';
import { hash, token } from '../apps/server/src/crypto.js';

const root = process.argv[2]!;
execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(root, 'key.pem'), '-out', join(root, 'cert.pem')], { stdio: 'pipe', windowsHide: true, timeout: 30000 });
const server = createServer({ key: readFileSync(join(root, 'key.pem')), cert: readFileSync(join(root, 'cert.pem')) });
await new Promise<void>(ok => server.listen(0, '127.0.0.1', ok));
const port = (server.address() as { port: number }).port, origin = 'https://127.0.0.1:' + port;
const masterKey = randomBytes(32); Authority.initialize(join(root, 'authority'), masterKey);
const service = await RinkService.open(new Authority(join(root, 'authority'), masterKey), join(root, 'state'), origin);
const hub = new TunnelHub(service); hub.attach(server);
const operations = new Operations(hub);
const invitation = await service.createInvitation({ helperName: 'Isolated login test', purpose: 'Disposable account only' }, randomUUID());
const browser = hash(token()), accepted = await service.accept(invitation.inviteUrl.split('/').at(-1)!, browser, randomUUID());
const boot = await service.bootstrap(browser, randomUUID());
// This observer token is fixture-only, independent of the real management API key.
const observer = '/fixture/' + randomUUID();
writeFileSync(join(root, 'input.json'), JSON.stringify({ observer, bootstrap: { v: 1, origin, sessionId: accepted.id, enrollmentId: boot.enrollmentId, bootstrapKey: boot.bootstrapKey, expiresAt: boot.expiresAt, instanceId: boot.instanceId, epoch: boot.epoch } }), { mode: 0o600 });
const managementKey = token();
if (process.argv.includes('--management')) writeFileSync(join(root, 'management.json'), JSON.stringify({ origin, apiKey: managementKey }), { mode: 0o600 });
const app = createApp(service, { PUBLIC_BASE_URL: origin, MCP_API_KEY: managementKey, MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey }, undefined, undefined, operations);
const authRejections = { wrongKey: 0, missingKey: 0 };
server.on('request', (req, res) => {
  if (process.argv.includes('--management') && req.url === '/mcp') res.once('finish', () => {
    if (res.statusCode !== 401) return;
    if (req.headers.authorization) authRejections.wrongKey++; else authRejections.missingKey++;
    writeFileSync(join(root, 'auth-rejections.json'), JSON.stringify(authRejections), { mode: 0o600 });
  });
  if (!req.url?.startsWith(observer)) { app(req, res); return; }
  void (async () => {
    if (req.url === observer && req.method === 'GET') return { ...service.summary(accepted.id), online: hub.online(accepted.id) };
    if (req.url === observer + '/probe' && req.method === 'POST') {
      const task = await operations.start(accepted.id, { command: 'id -un', shell: 'posix', timeoutSeconds: 10 }, randomUUID());
      const until = Date.now() + 15000;
      while (Date.now() < until) {
        const result = operations.get(task.executionId);
        if (!['queued', 'running'].includes(result.state)) return result;
        await new Promise(ok => setTimeout(ok, 50));
      }
      throw new Error('SSH probe timed out');
    }
    if (req.url === observer + '/revoke' && req.method === 'POST') return service.disconnect(accepted.id, 's_operator');
    throw new Error('Unknown fixture request');
  })().then(body => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)); }, () => { res.statusCode = 503; res.end('{}'); });
});
console.log(JSON.stringify({ port }));
let closing = false;
async function close() {
  if (closing) return; closing = true;
  await operations.close(); await hub.close(); server.closeAllConnections();
  await new Promise<void>(ok => server.close(() => ok())); await service.close();
}
process.stdin.resume(); process.stdin.once('end', () => { void close(); });
process.once('SIGTERM', () => { void close(); });
