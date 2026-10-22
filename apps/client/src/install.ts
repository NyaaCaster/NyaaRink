import { join } from 'node:path';
import { z } from 'zod';
import { Bootstrap, Enrollment, type BootstrapData } from '../../../packages/contracts/device.js';
import { VERSION } from '@nyaarink/version';
import { deviceMessage, deviceSign, hash } from '../../server/src/crypto.js';
import { DeviceApi } from './api.js';
import { changeKey } from './keys.js';
import { deviceKeys, StateStore, type State } from './state.js';
import { installLogin, localSsh, prepareSsh, privilegedAccount, removeLogin, verifyLoopback, type Confirm } from './platform.js';

export type InstallHooks = {
  confirm: Confirm; prepare: () => Promise<void>;
  inspect: () => ReturnType<typeof localSsh>; verify: typeof verifyLoopback;
  addKey: typeof changeKey; login: typeof installLogin; removeLogin: typeof removeLogin;
  privileged: () => boolean; request?: typeof fetch;
};
export function installHooks(confirm: Confirm, port: number): InstallHooks {
  return { confirm, prepare: () => prepareSsh(confirm), inspect: () => localSsh(port, confirm), verify: verifyLoopback,
    addKey: changeKey, login: installLogin, removeLogin, privileged: privilegedAccount };
}
export async function install(input: BootstrapData, store: StateStore, runtime: string, hooks: InstallHooks) {
  const bootstrap = Bootstrap.parse(input), unlock = store.lock();
  try {
    let state: State;
    if (store.exists()) {
      state = store.read();
      if (state.bootstrap.origin !== bootstrap.origin || state.bootstrap.instanceId !== bootstrap.instanceId || state.bootstrap.epoch !== bootstrap.epoch) throw new Error('Conflicting invitation identity');
      if (state.phase === 'revoked' || state.phase === 'cleaned') throw new Error('本次授权已主动撤销，不能重新安装');
      if (state.bootstrap.enrollmentId !== bootstrap.enrollmentId) {
        if (state.enrollment || state.phase !== 'preparing') throw new Error('不可替换已绑定身份');
        state.bootstrap = bootstrap; store.write(state);
      }
    } else {
      const pair = deviceKeys();
      state = { v: 1, bootstrap, devicePrivateKey: pair.privateKey, devicePublicKey: pair.publicKey,
        phase: 'preparing', runtime, cleanup: 'pending', reported: false, releaseVersion: VERSION };
      store.write(state); // Persist identity before enrollment so a lost response can be retried with the same key.
    }
    if (!await hooks.confirm(`S端：${bootstrap.origin}\n将允许协助者（可能含AI Agent）通过SSH以当前账户操作；断网不撤权，登录后自动恢复。只有主动断开才撤权。确认本次连接？`)) throw new Error('未确认本次配置，授权保持等待');
    if (hooks.privileged() && !await hooks.confirm('当前目标账户属于管理员/root，SSH操作也具有此权限。建议使用普通账户。是否明确授权高权限SSH？')) throw new Error('高权限授权未获确认');
    await hooks.prepare();
    const local = await hooks.inspect();
    console.log(`目标账户：${local.account}；回环SSH：${local.host}:${local.port}`);
    if (!await hooks.confirm('确认以上实际账户和本机SSH端口？')) throw new Error('账户确认取消；等待重试');
    await hooks.verify(local.host, local.port, local.hostKeys);
    const enrollment = Enrollment.parse({ sessionId: bootstrap.sessionId, enrollmentId: bootstrap.enrollmentId, devicePublicKey: state.devicePublicKey,
      account: local.account, home: local.home, shell: local.shell, platform: local.platform, host: local.host, port: local.port, hostKeys: local.hostKeys });
    if (state.enrollment && JSON.stringify(state.enrollment) !== JSON.stringify(enrollment)) throw new Error('本地账户或主机身份已改变，禁止自动更新绑定');
    state.enrollment = enrollment; state.authorizedKeys = local.authorizedKeys; store.write(state);
    const api = new DeviceApi(state, hooks.request);
    const result = z.object({ v: z.literal(1), instanceId: z.string().uuid(), epoch: z.string().uuid(), sessionId: z.string().uuid(), sshPublicKey: z.string() }).strict()
      .parse(await api.post('/api/v1/device/enroll', { data: enrollment, bootstrapKey: bootstrap.bootstrapKey,
        signature: deviceSign(state.devicePrivateKey!, deviceMessage('enroll', bootstrap.instanceId, bootstrap.epoch, bootstrap.sessionId, hash(bootstrap.bootstrapKey), enrollment)) }));
    if (result.instanceId !== bootstrap.instanceId || result.epoch !== bootstrap.epoch || result.sessionId !== bootstrap.sessionId) throw new Error('Enrollment response identity mismatch');
    state.sshPublicKey = result.sshPublicKey; state.phase = 'enrolled'; store.write(state);
    try {
      if (store.revoked()) throw new Error('本地撤销已生效；禁止继续安装');
      hooks.addKey(state.authorizedKeys!, bootstrap.sessionId, state.sshPublicKey, true);
      // Save the expected definition path before creating a task so failed registration is compensatable.
      state.loginFile = process.platform === 'win32' ? join(store.directory, 'login-task.xml') : join(local.home, '.config', 'systemd', 'user', `nyaarink-${bootstrap.sessionId}.service`);
      store.write(state); state.loginFile = hooks.login(state, store.directory);
      state.phase = 'ready'; store.write(state);
    } catch (error) {
      state.phase = store.revoked() ? 'revoked' : 'enrolled'; store.write(state);
      const failures: string[] = [];
      try { hooks.addKey(state.authorizedKeys!, bootstrap.sessionId, state.sshPublicKey, false); } catch { failures.push('本次公钥'); }
      try { hooks.removeLogin(state); } catch { failures.push('登录项'); }
      if (failures.length) throw new Error(`安装失败且待清理：${failures.join('、')}。授权保留；重试安装或主动断开。`);
      throw error;
    }
    return state;
  } finally { unlock(); }
}
export async function localRevoke(store: StateStore, hooks: Pick<InstallHooks, 'addKey' | 'removeLogin'>, request?: typeof fetch) {
  // The marker must win even if an installer currently owns the writer lock.
  store.markRevoked();
  const unlock = store.lock();
  try {
  const state = store.read();
  if (state.phase === 'cleaned') return state;
  state.phase = 'revoked'; state.cleanup = 'pending'; store.write(state);
  let failed = false;
  try { if (state.authorizedKeys && state.sshPublicKey) hooks.addKey(state.authorizedKeys, state.bootstrap.sessionId, state.sshPublicKey, false); } catch { failed = true; }
  // Keep the login runner until the signed offline revocation has been delivered.
  // Its permanent revoked marker permits cleanup only, never reconnecting SSH.
  state.cleanup = failed ? 'failed' : 'pending'; store.write(state);
  const api = new DeviceApi(state, request);
  try {
    await api.perform('disconnect'); state.reported = true; store.write(state);
    // Confirm removal of access material while the revoked-only retry runner
    // still exists. A dropped acknowledgment must not strand the outbox.
    await api.perform('cleanup-ack', { result: failed ? 'failed' : 'confirmed' });
    if (!failed) {
      try { hooks.removeLogin(state); } catch { failed = true; }
    }
    state.cleanup = failed ? 'failed' : 'confirmed'; store.write(state);
    if (!failed) {
      delete state.devicePrivateKey; delete state.sshPublicKey; state.bootstrap.bootstrapKey = '0'.repeat(43); state.phase = 'cleaned'; store.write(state);
    }
  } catch { /* Offline revocation remains durable. Keep only the proof necessary for signed retry. */ }
  return state;
  } finally { unlock(); }
}
