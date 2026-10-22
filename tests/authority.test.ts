import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, appendFileSync, writeFileSync, copyFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { Authority } from '../apps/server/src/authority.js';
import { RinkService, type EnrollmentData } from '../apps/server/src/service.js';
import { deviceMessage, deviceSign, hash, seal, token, unseal } from '../apps/server/src/crypto.js';
import { createApp } from '../apps/server/src/app.js';
import { maintain } from '../apps/server/src/maintenance.js';
import { execFileSync } from 'node:child_process';

const roots: string[] = [], services: RinkService[] = [], authorities: Authority[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const service of services.splice(0)) { try { await service.close(); } catch { /* Already closed in restart tests. */ } }
  for (const a of authorities.splice(0)) a.close();
  for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true });
});
function directory() { const root = mkdtempSync(join(tmpdir(), 'nyaarink-authority-')); roots.push(root); return root; }
async function setup() {
  const root = directory(), path = join(root, 'authority'), key = randomBytes(32);
  Authority.initialize(path, key); const a = new Authority(path, key); authorities.push(a);
  const service = await RinkService.open(a, join(root, 'state'), 'https://example.invalid:5116'); services.push(service);
  return { root, path, key, a, service };
}
async function accept(service: RinkService) {
  const invitation = await service.createInvitation({ helperName: 'Helper', purpose: 'Repair' }, randomUUID());
  const code = invitation.inviteUrl.split('/').at(-1)!, browserHash = hash(token());
  const accepted = await service.accept(code, browserHash, randomUUID()); return { invitation, code, browserHash, id: accepted.id };
}
async function enroll(service: RinkService) {
  const accepted = await accept(service), boot = await service.bootstrap(accepted.browserHash, randomUUID());
  const pair = generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  const data: EnrollmentData = { sessionId: accepted.id, enrollmentId: boot.enrollmentId!, devicePublicKey: pair.publicKey,
    account: 'ordinary', home: '/home/ordinary', shell: 'posix', platform: 'linux', host: '127.0.0.1', port: 22, hostKeys: [randomBytes(64).toString('base64')] };
  const signature = deviceSign(pair.privateKey, deviceMessage('enroll', boot.instanceId!, boot.epoch!, data.sessionId, hash(boot.bootstrapKey!), data));
  const result = await service.enroll(data, boot.bootstrapKey!, signature);
  return { ...accepted, boot, pair, data, signature, result };
}
describe('authority crash and integrity boundaries', () => {
  it('replays cumulative metrics without changing authorization and rejects regression', async () => {
    const { service, path, key, root } = await setup(), { id } = await accept(service);
    const value = { sshBytesSToC: 13, sshBytesCToS: 21, sshConnectionsOpened: 2, onlineSeconds: 1.5, apiOperations: 1 };
    await service.saveMetrics(id, value);
    const count = service.authority.events.length;
    await service.saveMetrics(id, value); expect(service.authority.events).toHaveLength(count);
    await expect(service.saveMetrics(id, { ...value, sshBytesSToC: 0 })).rejects.toThrow('regressed');
    await service.close(); services.splice(services.indexOf(service), 1);
    const restored = await RinkService.open(new Authority(path, key), join(root, 'state'), service.origin); services.push(restored);
    expect(restored.savedMetrics(id)).toEqual(value);
    expect(restored.summary(id).authorization).toBe('accepted');
  });
  it('refuses missing authority, wrong master key and a second writer', async () => {
    const missing = new Authority(directory(), randomBytes(32)); authorities.push(missing); expect(missing.frozen).toBe(true);
    const { path, key, a } = await setup();
    const second = new Authority(path, key); authorities.push(second); expect(second.frozen).toBe(true);
    expect(a.frozen).toBe(false); a.close();
    const wrong = new Authority(path, randomBytes(32)); authorities.push(wrong); expect(wrong.frozen).toBe(true);
  });
  it('ignores only an uncommitted partial tail, advances an old head, and refuses a missing committed frame', () => {
    const root = directory(), key = randomBytes(32); Authority.initialize(root, key);
    const originalHead = readFileSync(join(root, 'head.json'));
    let a = new Authority(root, key); a.append('test', { value: 1 }); a.close();
    writeFileSync(join(root, 'head.json'), originalHead);
    appendFileSync(join(root, 'events.bin'), Buffer.from([0, 0, 1]));
    a = new Authority(root, key); expect(a.frozen).toBe(false); expect(a.events).toHaveLength(1); a.close();
    const currentHead = readFileSync(join(root, 'head.json'));
    writeFileSync(join(root, 'events.bin'), Buffer.alloc(0)); writeFileSync(join(root, 'head.json'), currentHead);
    a = new Authority(root, key); authorities.push(a); expect(a.frozen).toBe(true);
  });
  it('detects complete-frame tampering', () => {
    const root = directory(), key = randomBytes(32); Authority.initialize(root, key);
    let a = new Authority(root, key); a.append('test', { value: 1 }); a.close();
    const file = join(root, 'events.bin'), bytes = readFileSync(file); bytes[bytes.length - 8] = bytes[bytes.length - 8]! ^ 1; writeFileSync(file, bytes);
    a = new Authority(root, key); authorities.push(a); expect(a.frozen).toBe(true);
  });
  it.each(['before_append', 'after_fsync'])('freezes immediately on injected %s failure', point => {
    const root = directory(), key = randomBytes(32); Authority.initialize(root, key);
    const a = new Authority(root, key, current => { if (current === point) throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); });
    expect(() => a.append('test', {})).toThrow('FROZEN'); expect(a.frozen).toBe(true); a.close();
    const recovered = new Authority(root, key); authorities.push(recovered); expect(recovered.frozen).toBe(false); expect(recovered.events.length).toBe(point === 'after_fsync' ? 1 : 0);
  });
  it('binds vault objects to both identity and object id; ciphertext contains no private data', () => {
    const key = randomBytes(32), encoded = seal(key, { private: 'secret marker' }, 'one');
    expect(encoded).not.toContain('secret marker'); expect(unseal(key, encoded, 'one')).toEqual({ private: 'secret marker' });
    expect(() => unseal(key, encoded, 'two')).toThrow();
  });
});
describe('single-use consent, enrollment and durable revocation', () => {
  it('GET preview never consumes; concurrent browsers produce exactly one accepted session', async () => {
    const { service } = await setup();
    const invite = await service.createInvitation({ helperName: 'Name', purpose: 'Purpose' }, randomUUID()), code = invite.inviteUrl.split('/').at(-1)!;
    const browsers = Array.from({ length: 8 }, () => hash(token()));
    for (const b of browsers) expect(service.invitationPage(code, b)).toHaveProperty('state', 'issued');
    expect(service.sessions.size).toBe(0);
    const results = await Promise.allSettled(browsers.map(b => service.accept(code, b, randomUUID())));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1); expect(service.sessions.size).toBe(1);
    const winner = browsers[results.findIndex(r => r.status === 'fulfilled')]!;
    expect(service.invitationPage(code, winner)).toHaveProperty('authorization', 'accepted');
    expect(() => service.invitationPage(code, hash(token()))).toThrow('INVITATION_UNAVAILABLE');
  });
  it('accept retry survives restart; conflicting idempotency input refuses reuse', async () => {
    const { service, path, key, root } = await setup(), requestId = randomUUID(), browser = hash(token());
    const invite = await service.createInvitation({ helperName: 'Name', purpose: 'Purpose' }, randomUUID()), code = invite.inviteUrl.split('/').at(-1)!;
    const first = await service.accept(code, browser, requestId);
    expect((await service.accept(code, browser, requestId)).id).toBe(first.id);
    await expect(service.accept(token(), browser, requestId)).rejects.toThrow('CONFLICT');
    await service.close(); const a = new Authority(path, key); authorities.push(a);
    const restarted = await RinkService.open(a, join(root, 'state'), service.origin); services.push(restarted);
    expect((await restarted.accept(code, browser, requestId)).id).toBe(first.id);
  });
  it('replaces bootstrap; rejects the old script and different devices; same-device signed retry works', async () => {
    const { service } = await setup(), c = await accept(service);
    const first = await service.bootstrap(c.browserHash, randomUUID()), next = await service.bootstrap(c.browserHash, randomUUID());
    expect(first.bootstrapKey).not.toBe(next.bootstrapKey);
    const pair = generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    const data: EnrollmentData = { sessionId: c.id, enrollmentId: first.enrollmentId!, devicePublicKey: pair.publicKey, account: 'normal', home: '/home/normal', shell: 'posix', platform: 'linux', host: '127.0.0.1', port: 22, hostKeys: [randomBytes(64).toString('base64')] };
    const signature = deviceSign(pair.privateKey, deviceMessage('enroll', first.instanceId!, first.epoch!, c.id, hash(first.bootstrapKey!), data));
    await expect(service.enroll(data, first.bootstrapKey!, signature)).rejects.toThrow('UNAUTHORIZED');
    const enrolled = await enroll(service);
    expect((await service.enroll(enrolled.data, enrolled.boot.bootstrapKey!, enrolled.signature)).sshPublicKey).toBe(enrolled.result.sshPublicKey);
    const changed = { ...enrolled.data, account: 'root' };
    const changedSignature = deviceSign(enrolled.pair.privateKey, deviceMessage('enroll', enrolled.boot.instanceId!, enrolled.boot.epoch!, enrolled.id, hash(enrolled.boot.bootstrapKey!), changed));
    await expect(service.enroll(changed, enrolled.boot.bootstrapKey!, changedSignature)).rejects.toThrow('CONFLICT');
    expect(enrolled.result).not.toHaveProperty('sshPrivate'); expect(enrolled.result.sshPublicKey).toMatch(/^ssh-ed25519 /);
  });
  it('has no authorization expiry, requires one-use device proof, and permits only cleanup after revocation', async () => {
    const { service } = await setup(), c = await enroll(service);
    expect(service.summary(c.id)).toHaveProperty('authorization', 'enrolled');
    const challenge = service.challenge(c.id, 'disconnect');
    const sig = deviceSign(c.pair.privateKey, deviceMessage('disconnect', challenge.instanceId, challenge.epoch, c.id, challenge.nonce, {}));
    expect(await service.deviceDisconnect(c.id, challenge.nonce, sig)).toMatchObject({ authorization: 'revoked', sCleanup: 'confirmed', cCleanup: 'pending' });
    expect(() => service.deviceDisconnect(c.id, challenge.nonce, sig)).toThrow('UNAUTHORIZED');
    expect(() => service.credentials(c.id)).toThrow('REVOKED');
    // A revoked device may reconnect only to receive revoke and perform cleanup.
    const reconnect = service.challenge(c.id, 'control');
    const hello = { protocolVersion: 1, devicePublicKey: c.data.devicePublicKey };
    expect(await service.activate(c.id, reconnect.nonce, hello, deviceSign(c.pair.privateKey, deviceMessage('control', reconnect.instanceId, reconnect.epoch, c.id, reconnect.nonce, hello)))).toMatchObject({ revoked: true, generation: 0 });
    expect(() => service.browserSession(c.browserHash)).toThrow('NOT_FOUND');
    const ack = service.challenge(c.id, 'cleanup-ack');
    const ackSig = deviceSign(c.pair.privateKey, deviceMessage('cleanup-ack', ack.instanceId, ack.epoch, c.id, ack.nonce, { result: 'confirmed' }));
    expect(await service.cleanupAck(c.id, 'confirmed', ack.nonce, ackSig)).toHaveProperty('cCleanup', 'confirmed');
    expect(await service.disconnect(c.id, 's_operator')).toHaveProperty('authorization', 'revoked');
    expect(() => service.authority.secret(c.id)).toThrow('FROZEN');
  });
  it('browser recovery replaces the old browser without replacing device or authority', async () => {
    const { service } = await setup(), c = await enroll(service), next = hash(token());
    const recover = service.recovery(next), challenge = service.challenge(c.id, 'recover-browser');
    const signature = deviceSign(c.pair.privateKey, deviceMessage('recover-browser', challenge.instanceId, challenge.epoch, c.id, challenge.nonce, { code: recover.code }));
    await service.recoverBrowser(c.id, recover.code, challenge.nonce, signature);
    expect(service.browserSession(next)).toHaveProperty('id', c.id); expect(() => service.browserSession(c.browserHash)).toThrow('NOT_FOUND');
    expect(service.credentials(c.id).device.devicePublicKey).toBe(c.pair.publicKey);
  });
  it('keeps enrolled permission after a year of offline time without a disconnect command', async () => {
    const { service } = await setup(), c = await enroll(service);
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 366 * 24 * 3600000);
    expect(service.credentials(c.id).sshPublic).toBe(c.result.sshPublicKey);
    expect(service.summary(c.id)).toMatchObject({ authorization: 'enrolled', connectivity: 'offline' });
  });
  it('cleans remaining secrets on restart after revoke was committed but cleanup was interrupted', async () => {
    const { service, a, path, key, root } = await setup(), c = await enroll(service);
    a.append('revoke', { id: c.id, actor: 's_operator' }); // Simulate a crash at the durable commit point.
    await service.close(); const reopened = new Authority(path, key); authorities.push(reopened);
    const recovered = await RinkService.open(reopened, join(root, 'state'), service.origin); services.push(recovered);
    expect(recovered.summary(c.id)).toMatchObject({ authorization: 'revoked', sCleanup: 'confirmed' });
    expect(readdirSync(join(path, 'vault'))).not.toContain(c.id + '.json');
  });
  it('old database restore replays new valid sessions and never revives revoked sessions', async () => {
    const { service, root, key, path } = await setup(), old = await enroll(service);
    const backup = await service.projection.backup(service.authority);
    const fresh = await enroll(service); await service.disconnect(old.id, 's_operator'); await service.close();
    // The service already made consistent backups before every DB mutation. This replacement is an isolated restore test.
    copyFileSync(backup, join(root, 'state', 'state.db'));
    const a = new Authority(path, key); authorities.push(a);
    const recovered = await RinkService.open(a, join(root, 'state'), service.origin); services.push(recovered);
    expect(recovered.summary(old.id)).toHaveProperty('authorization', 'revoked');
    expect(recovered.credentials(fresh.id).sshPublic).toBe(fresh.result.sshPublicKey);
    const row = recovered.projection.db.prepare('SELECT seq FROM snapshot').get() as { seq: number };
    expect(row.seq).toBe(a.events.length); expect(readdirSync(join(root, 'state', 'backups')).length).toBeGreaterThan(0);
  });
  it('freezes if a database comes from a different authority', async () => {
    const first = await setup(); await accept(first.service); const backup = await first.service.projection.backup(first.a);
    const second = directory(), authPath = join(second, 'authority'), key = randomBytes(32); Authority.initialize(authPath, key);
    mkdirSync(join(second, 'state')); copyFileSync(backup, join(second, 'state', 'state.db'));
    const a = new Authority(authPath, key); authorities.push(a);
    await expect(RinkService.open(a, join(second, 'state'), first.service.origin)).rejects.toThrow(); expect(a.frozen).toBe(true);
  });
  it('online Python DB backup and offline verification/recovery preserve the latest authorization', async () => {
    const { service, a, root, path, key } = await setup(), old = await enroll(service);
    const keyPath = join(root, 'master.key'); writeFileSync(keyPath, key, { mode: 0o600 });
    const state = join(root, 'state');
    const backup = execFileSync('python', ['-c', 'import backup, sys; print(backup.backup_database(sys.argv[1]))', state], { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } }).trim();
    const fresh = await enroll(service); await service.disconnect(old.id, 's_operator');
    const env = { AUTHORITY_DIR: path, STATE_DIR: state, SESSION_MASTER_KEY_FILE: keyPath, PUBLIC_BASE_URL: service.origin };
    await expect(maintain('backup-authority', undefined, env)).rejects.toThrow('FROZEN');
    await service.close();
    const before = hash(readFileSync(join(path, 'head.json')));
    expect(await maintain('verify-authority', undefined, env)).toHaveProperty('verified', true);
    expect(hash(readFileSync(join(path, 'head.json')))).toBe(before);
    expect(await maintain('restore-database', backup, env)).toHaveProperty('restored', true);
    const reopened = new Authority(path, key); authorities.push(reopened);
    const current = await RinkService.open(reopened, state, service.origin); services.push(current);
    expect(current.summary(old.id).authorization).toBe('revoked'); expect(current.credentials(fresh.id).sshPublic).toBe(fresh.result.sshPublicKey);
    expect(a.identity).toEqual(reopened.identity);
  });
  it('a database newer than authority freezes instead of silently rebuilding backwards', async () => {
    const { service, root, path, key } = await setup();
    const head = readFileSync(join(path, 'head.json')), ledger = readFileSync(join(path, 'events.bin'));
    await accept(service); await service.close();
    writeFileSync(join(path, 'head.json'), head); writeFileSync(join(path, 'events.bin'), ledger);
    const a = new Authority(path, key); authorities.push(a);
    await expect(RinkService.open(a, join(root, 'state'), service.origin)).rejects.toThrow(); expect(a.frozen).toBe(true);
  });
});
it('HTTP boundary enforces bearer, exact Host/Origin, consent CSRF, no-store and invalid refresh after revoke', async () => {
  const { service, key } = await setup(), apiKey = token();
  const config = { PUBLIC_BASE_URL: '', MCP_API_KEY: apiKey, MCP_API_KEY_PREVIOUS: '', API_KEY_PREVIOUS_UNTIL: '', masterKey: key };
  // Router creation needs the eventual port; reserve it with a forwarding listener before constructing the app.
  const { createServer } = await import('node:http');
  let app: ReturnType<typeof createApp>;
  const server = createServer((req, res) => app(req, res)); server.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('No test port');
  const url = `http://127.0.0.1:${address.port}`; config.PUBLIC_BASE_URL = `https://127.0.0.1:${address.port}`; app = createApp(service, config);
  try {
    const body = { helperName: 'Helper', purpose: 'Repair' }, id = randomUUID();
    const create = (headers: Record<string, string>) => fetch(url + '/api/v1/invitations', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': id, ...headers }, body: JSON.stringify(body) });
    expect((await create({})).status).toBe(401);
    expect((await create({ Authorization: `Bearer ${apiKey}`, Origin: 'https://evil.invalid' })).status).toBe(403);
    const invitation = await (await create({ Authorization: `Bearer ${apiKey}` })).json() as { inviteUrl: string };
    const code = invitation.inviteUrl.split('/').at(-1)!;
    const page = await fetch(url + '/api/v1/browser/invitation?code=' + code);
    const cookie = page.headers.get('set-cookie')!.split(';')[0]!, context = await page.json() as { csrf: string };
    expect(page.headers.get('cache-control')).toBe('no-store'); expect(service.sessions.size).toBe(0);
    const accept = (headers: Record<string, string>) => fetch(url + '/api/v1/invitations/accept', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, 'Idempotency-Key': randomUUID(), ...headers }, body: JSON.stringify({ code, consent: true }) });
    expect((await accept({ Origin: config.PUBLIC_BASE_URL })).status).toBe(403);
    const consent = await accept({ Origin: config.PUBLIC_BASE_URL, 'X-NR-CSRF': context.csrf }); expect(consent.status).toBe(200);
    const session = await consent.json() as { id: string };
    const revoked = await fetch(url + '/api/v1/browser/disconnect', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: config.PUBLIC_BASE_URL, 'X-NR-CSRF': context.csrf }, body: JSON.stringify({ sessionId: session.id }) }); expect(revoked.status).toBe(200);
    expect((await fetch(url + '/api/v1/browser/session', { headers: { Cookie: cookie } })).status).toBe(404);
    expect((await fetch(url + '/api/v1/browser/invitation?code=' + code, { headers: { Cookie: cookie } })).status).toBe(404);
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});
