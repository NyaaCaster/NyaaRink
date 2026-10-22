import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { parseArgs } from 'node:util';
import { dirname, resolve } from 'node:path';
import { BLESSING, VERSION } from '@nyaarink/version';
import { Bootstrap } from '../../../packages/contracts/device.js';
import { install, installHooks, localRevoke } from './install.js';
import { DeviceApi } from './api.js';
import { StateStore } from './state.js';
import { installRuntime } from './runtime.js';
import { runTunnel } from './tunnel.js';

async function confirm(text: string) {
  if (!stdin.isTTY) throw new Error('需要交互终端确认，请在本机终端运行');
  const terminal = createInterface({ input: stdin, output: stdout });
  try { return (await terminal.question(`${text}\n输入 YES 继续：`)).trim() === 'YES'; } finally { terminal.close(); }
}
async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    version: { type: 'boolean' }, session: { type: 'string' }, bootstrap: { type: 'string' }, port: { type: 'string' },
  } });
  if (values.version) { console.log(`NyaaRink client ${VERSION} | ${BLESSING}`); return; }
  const [command, code] = positionals;
  const port = Number(values.port ?? '22');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('无效SSH端口');
  const hooks = installHooks(confirm, port);
  if (command === 'install') {
    if (!values.bootstrap) throw new Error('缺少 --bootstrap 文件');
    const data = readFileSync(values.bootstrap); if (data.length > 16384) throw new Error('引导文件过大');
    const bootstrap = Bootstrap.parse(JSON.parse(data.toString()));
    if (!values.port) {
      if (!stdin.isTTY) throw new Error('需要在本机交互终端确认SSH端口');
      const terminal = createInterface({ input: stdin, output: stdout });
      let selected: number;
      try { selected = Number((await terminal.question('本机SSH端口 [22]：')).trim() || '22'); } finally { terminal.close(); }
      if (!Number.isInteger(selected) || selected < 1 || selected > 65535) throw new Error('无效SSH端口');
      Object.assign(hooks, installHooks(confirm, selected));
    }
    const runtime = installRuntime(dirname(resolve(process.argv[1]!)));
    const store = new StateStore(bootstrap.sessionId);
    await install(bootstrap, store, runtime, hooks);
    console.log(`本地准备完成；会话 ${bootstrap.sessionId}。断网不撤权。`);
    await runTunnel(store, () => localRevoke(store, hooks)); return;
  }
  if (!values.session) throw new Error('用法：status|resume|resume-browser <code>|disconnect|cleanup --session <UUID>');
  const store = new StateStore(values.session), state = store.read();
  if (command === 'status') {
    console.log(JSON.stringify({ sessionId: values.session, phase: state.phase, cleanup: state.cleanup, reported: state.reported, origin: state.bootstrap.origin }, null, 2)); return;
  }
  if (command === 'disconnect') {
    if (!await confirm('将永久撤销本次SSH访问并终止操作。网络断开无需执行此命令。确认主动断开？')) return;
    const result = await localRevoke(store, hooks);
    console.log(result.phase === 'cleaned' ? '已断开并清理，请删除本次连接脚本或 ZIP 包及全部解压副本。' : '本地已撤销，清理或补交待完成；禁止恢复访问。'); return;
  }
  if (command === 'cleanup' || command === 'resume') {
    if (state.phase === 'revoked') {
      const result = await localRevoke(store, hooks);
      if (result.phase !== 'cleaned') throw new Error('本地撤销保持生效；清理/补交待重试');
      return;
    }
    if (state.phase === 'cleaned') return;
    if (command === 'cleanup') throw new Error('有效授权不能作为垃圾清理，请显式disconnect');
    await runTunnel(store, () => localRevoke(store, hooks)); return;
  }
  if (command === 'resume-browser') {
    if (state.phase !== 'ready' || !code || !/^[A-Z2-7]{12}$/.test(code)) throw new Error('需要有效会话和12位恢复码');
    if (!await confirm(`将此会话页面绑定至配对码 ${code} 对应浏览器，确认？`)) return;
    await new DeviceApi(state).perform('recover-browser', { code }); console.log('浏览器已恢复'); return;
  }
  throw new Error('未知命令');
}
main().catch(error => { console.error(error instanceof Error ? error.message : '客户端操作失败'); process.exitCode = 1; });
