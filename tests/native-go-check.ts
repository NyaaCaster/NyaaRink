// Opt-in, loopback-only integration of the signed Go client and real S service.
import { strict as assert } from 'node:assert';
import { createServer } from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { unzipSync } from 'fflate';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService } from '../apps/server/src/service.js';
import { TunnelHub } from '../apps/server/src/tunnel.js';
import { createApp } from '../apps/server/src/app.js';
import { Artifacts, windowsConnectionPackage } from '../apps/server/src/artifacts.js';
import { hash, token } from '../apps/server/src/crypto.js';

const go = process.env.NYAARINK_GO, artifactsDir = process.env.NYAARINK_GO_ARTIFACTS;
if (!go || !artifactsDir || process.platform !== 'win32') throw new Error('Explicit Windows Go toolchain and signed artifacts required');
const root = mkdtempSync(join(tmpdir(), 'nyaarink-go-check-'));
let service: RinkService | undefined, hub: TunnelHub | undefined;
const server = createServer();
try {
  const cert = join(root, 'test.crt'), privateKey = join(root, 'test.key');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', privateKey, '-out', cert, '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'pipe', windowsHide: true, timeout: 30000 });
  server.setSecureContext({ key: readFileSync(privateKey), cert: readFileSync(cert) });
  await new Promise<void>(ok => server.listen(0, '127.0.0.1', ok));
  const origin = 'https://127.0.0.1:' + (server.address() as { port: number }).port;
  const masterKey = randomBytes(32), secret = token();
  Authority.initialize(join(root, 'authority'), masterKey);
  service = await RinkService.open(new Authority(join(root, 'authority'), masterKey), join(root, 'db'), origin);
  hub = new TunnelHub(service); hub.attach(server);
  const activeService = service;
  const invite = await service.createInvitation({ helperName: 'Native integration', purpose: 'Disposable test only' }, randomUUID());
  const browser = hash(token());
  const { id } = await service.accept(invite.inviteUrl.split('/').at(-1)!, browser, randomUUID());
  const boot = await service.bootstrap(browser, randomUUID());
  const bootstrap = { v: 1, sessionId: id, enrollmentId: boot.enrollmentId!, bootstrapKey: boot.bootstrapKey!, expiresAt: boot.expiresAt!, origin, instanceId: boot.instanceId!, epoch: boot.epoch! };
  const artifacts = new Artifacts(resolve(artifactsDir)), artifact = artifacts.get('win32');
  assert.equal(artifact.runtime, 'go');
  const archive = readFileSync(join(artifactsDir, artifact.filename)), runtime = join(root, 'runtime'); mkdirSync(runtime);
  for (const [name, data] of Object.entries(unzipSync(archive))) { assert.match(name, /^[\w.-]+$/); writeFileSync(join(runtime, name), data); }
  const executable = join(runtime, 'nyaarink-client.exe');
  const verify = () => execFileSync(executable, ['verify', '--directory', runtime], { stdio: 'pipe', windowsHide: true });
  verify();
  const license = join(runtime, 'LICENSE'), originalLicense = readFileSync(license);
  writeFileSync(license, Buffer.concat([originalLicense, Buffer.from('tampered')]));
  assert.throws(verify, 'signed file tampering must fail'); writeFileSync(license, originalLicense);
  const signature = join(runtime, 'manifest.sig'), originalSignature = readFileSync(signature);
  writeFileSync(signature, Buffer.alloc(64)); assert.throws(verify, 'manifest signature tampering must fail'); writeFileSync(signature, originalSignature);
  const extra = join(runtime, 'extra.dll'); writeFileSync(extra, 'unexpected');
  assert.throws(verify, 'unlisted file must fail'); rmSync(extra); verify();
  const outer = windowsConnectionPackage(bootstrap, artifact, archive);
  assert.deepEqual(Object.keys(unzipSync(outer)).sort(), ['README.txt', 'bootstrap.json', 'client-runtime.zip', 'start.bat']);
  console.log(`Native Windows runtime ${archive.length} bytes; complete connection ZIP ${outer.length} bytes`);
  server.on('request', (req, res) => {
    if (req.url !== '/fixture') return;
    void (async () => {
      assert.equal(req.headers.authorization, 'Bearer ' + secret);
      let data = ''; for await (const chunk of req) { data += String(chunk); assert.ok(data.length < 8192); }
      const body = JSON.parse(data) as { action: string; path?: string };
      if (body.action === 'online') { res.end(JSON.stringify({ online: hub!.online(id), authorization: activeService.sessions.get(id)!.authorization })); return; }
      if (body.action === 'cut') { await hub!.close(); hub = new TunnelHub(activeService); hub.attach(server); res.end('{}'); return; }
      if (body.action === 'disconnect') { await activeService.disconnect(id, 's_operator'); res.end('{}'); return; }
      if (body.action === 'exercise') {
        assert.ok(hub!.online(id));
        const client = await hub!.connect(id);
        try {
          for (const pty of [false, true]) await new Promise<void>((ok, fail) => client.exec('cmd.exe /d /c echo NYAARINK_GO_E2E', { pty }, (error, channel) => {
            if (error) return fail(error); let output = ''; channel.on('data', (b: Buffer) => { output += b.toString(); }); channel.stderr.resume(); channel.on('error', fail);
            channel.on('close', (code: number) => { try { assert.equal(code, 0); assert.match(output, /NYAARINK_GO_E2E/); ok(); } catch (e) { fail(e); } });
          }));
          const path = body.path!; assert.ok(path.startsWith(root));
          await new Promise<void>((ok, fail) => client.sftp((error, sftp) => {
            if (error) return fail(error); sftp.on('error', fail);
            sftp.writeFile(path, Buffer.from('NyaaRink SFTP roundtrip'), error => {
              if (error) { sftp.end(); fail(error); return; }
              sftp.readFile(path, (error, content) => {
                if (error) { sftp.end(); fail(error); return; }
                try { assert.equal(content.toString(), 'NyaaRink SFTP roundtrip'); } catch (e) { sftp.end(); fail(e); return; }
                sftp.unlink(path, error => { sftp.end(); error ? fail(error) : ok(); });
              });
            });
          }));
        } finally { client.end(); }
        res.end('{}'); return;
      }
      throw new Error('Invalid fixture action');
    })().catch(e => { console.error('Fixture failed:', e instanceof Error ? e.message : 'unknown'); res.statusCode = 500; res.end('{}'); });
  });
  const app = createApp(service, { PUBLIC_BASE_URL: origin, MCP_API_KEY: secret, MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey });
  server.on('request', (req, res) => { if (req.url !== '/fixture') app(req, res); });
  const mode = process.env.NYAARINK_GO_REVOKE === 'local' ? 'local' : 'server';
  const input = join(root, 'input.json'); writeFileSync(input, JSON.stringify({ bootstrap, cert, runtime, root, secret, mode }), { mode: 0o600 });
  const child = spawn(go, ['test', '-count=1', '-run', 'TestNativeServer', '-v', '.'], { cwd: resolve('apps/client-native'), env: { ...process.env, NYAARINK_GO_FIXTURE: input }, stdio: 'inherit', windowsHide: true });
  const code = await new Promise<number | null>((ok, fail) => { child.once('error', fail); child.once('exit', ok); });
  assert.equal(code, 0, 'Go real-server integration');
  assert.equal(service.sessions.get(id)!.authorization, 'revoked');
  console.log(`Real HTTPS enrollment, WSS, exec/PTY/SFTP, network recovery and ${mode} revocation passed`);
} finally {
  await hub?.close(); server.closeAllConnections(); await new Promise<void>(ok => server.close(() => ok())); await service?.close(); rmSync(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
