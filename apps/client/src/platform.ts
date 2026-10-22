import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { userInfo, homedir } from 'node:os';
import { Client, utils } from 'ssh2';
import { durableWrite } from '../../server/src/crypto.js';
import type { State } from './state.js';
import { privatePath } from './state.js';
import { windowsEnvironment } from './windows.js';
export type Confirm = (text: string) => Promise<boolean>;
export function run(command: string, args: string[], env?: NodeJS.ProcessEnv) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, timeout: 60000, env: env ?? process.env }).trim();
}
export const windows = () => process.platform === 'win32';
export function powershell(script: string, env?: NodeJS.ProcessEnv) { return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop";' + script], windowsEnvironment(env)); }
export function supportedSshVersion(text: string) {
  const version = /OpenSSH(?:_for_Windows)?_(\d+)\.(\d+)/.exec(text);
  return !!version && (Number(version[1]) > 8 || (Number(version[1]) === 8 && Number(version[2]) >= 9));
}
export function requireSshVersion() {
  const result = spawnSync(sshdExecutable(), ['-?'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  if (!supportedSshVersion((result.stdout ?? '') + (result.stderr ?? ''))) throw new Error('需要OpenSSH 8.9或更新版本；请由C端确认升级，未改动现有服务或授权');
}
export function privilegedAccount() {
  if (!windows()) return process.getuid!() === 0;
  return powershell('$id=[System.Security.Principal.WindowsIdentity]::GetCurrent(); $id.Groups.Value -contains "S-1-5-32-544"') === 'True';
}
export function sshdExecutable() {
  return windows() ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'OpenSSH', 'sshd.exe') : '/usr/sbin/sshd';
}
export function serviceStatus(): 'missing' | 'stopped' | 'running' {
  if (windows()) {
    const status = powershell('$s=Get-Service sshd -ErrorAction SilentlyContinue; if($s){$s.Status}else{"Missing"}');
    return status === 'Running' ? 'running' : status === 'Missing' ? 'missing' : 'stopped';
  }
  if (!existsSync(sshdExecutable())) return 'missing';
  try { run('systemctl', ['is-active', '--quiet', 'ssh']); return 'running'; } catch { return 'stopped'; }
}
export async function prepareSsh(confirm: Confirm) {
  const status = serviceStatus(); if (status === 'running') return;
  const text = status === 'missing'
    ? '将使用系统组件/apt安装 OpenSSH Server，启动并启用SSH系统服务；系统安装器可能创建入站规则，需检查防火墙变化。本项目只连接回环，不自动放行端口。安装服务的提权不授予管理员SSH权限。是否继续？'
    : 'SSH服务未运行，将启动并启用SSH系统服务，不覆盖原配置或修改防火墙。是否继续？';
  if (!await confirm(text)) throw new Error('SSH准备未获确认；会话保留等待状态');
  if (windows()) {
    // Only this fixed system operation is elevated; no downloaded executable or user file is run as admin.
    const script = "$ErrorActionPreference='Stop'; if(-not (Get-Service sshd -ErrorAction SilentlyContinue)){ Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }; Set-Service sshd -StartupType Automatic; Start-Service sshd";
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const result = powershell(`$p=Start-Process -FilePath "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -Verb RunAs -ArgumentList @('-NoProfile','-EncodedCommand','${encoded}') -Wait -PassThru; $p.ExitCode`);
    if (result !== '0') throw new Error('SSH服务准备失败或UAC被拒绝；授权保留');
  } else {
    const script = 'set -eu; if ! test -x /usr/sbin/sshd; then apt-get update; apt-get install -y openssh-server; fi; systemctl enable --now ssh';
    // Fixed command only; sudo prompts on the local terminal and never sends a password to S.
    await new Promise<void>((ok, fail) => {
      const child = spawn('sudo', ['--', '/bin/sh', '-c', script], { stdio: 'inherit' }); child.on('error', fail); child.on('exit', code => code === 0 ? ok() : fail(new Error('SSH准备提权失败；授权保留')));
    });
  }
  if (serviceStatus() !== 'running') throw new Error('SSH服务仍不可用；未授权上线');
}
export async function localSsh(port: number, confirm: Confirm) {
  requireSshVersion();
  const account = userInfo().username, home = homedir();
  if (!/^[\w.@ -]+$/.test(account)) throw new Error('Unsupported local account name');
  const args = ['-T', '-C', `user=${account},host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=${port}`];
  let text: string;
  try { text = run(sshdExecutable(), args); }
  catch (error) {
    if (windows() || !await confirm('需要本地sudo只读检查目标账户的有效sshd配置，不更改账户、不上传私钥。是否继续？')) throw error;
    const result = spawnSync('sudo', ['--', sshdExecutable(), ...args], { stdio: ['inherit', 'pipe', 'pipe'], encoding: 'utf8' });
    if (result.status !== 0) throw new Error('无法检查有效SSH配置；授权保留等待'); text = result.stdout;
  }
  const options = new Map(text.split(/\r?\n/).map(line => { const at = line.indexOf(' '); return [line.slice(0, at), line.slice(at + 1)] as const; }));
  if (options.get('pubkeyauthentication') !== 'yes' || options.get('authorizedkeyscommand') !== 'none') throw new Error('SSH public-key configuration unsupported; no global settings changed');
  const paths = options.get('authorizedkeysfile')?.split(/\s+/) ?? [];
  const raw = paths[0]; if (!raw || raw === 'none') throw new Error('No authorized_keys path');
  const expanded = raw.replaceAll('__PROGRAMDATA__', process.env.ProgramData ?? 'C:\\ProgramData').replaceAll('%h', home).replaceAll('%u', account).replaceAll('%%', '%');
  if (/%[a-zA-Z]/.test(expanded)) throw new Error('Unsupported SSH path expansion');
  const authorizedKeys = isAbsolute(expanded) ? expanded : resolve(home, expanded);
  // Shared administrator file requires privileged permissions and is never silently treated as the user file.
  const administrator = windows() && /administrators_authorized_keys/i.test(authorizedKeys);
  if (administrator) {
    const elevated = powershell('([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)') === 'True';
    if (!elevated) throw new Error('此管理员账户使用共享administrators_authorized_keys；如明确要授予管理员SSH，请用同一账户提升运行，否则改用普通账户');
  }
  const hostKeyPaths = text.split(/\r?\n/).filter(line => line.startsWith('hostkey ')).map(line => line.slice(8) + '.pub');
  const hostKeys = hostKeyPaths.filter(existsSync).map(path => {
    const key = utils.parseKey(readFileSync(path)); if (key instanceof Error || Array.isArray(key)) throw new Error('Invalid local host public key');
    return key.getPublicSSH().toString('base64');
  });
  if (!hostKeys.length) throw new Error('Cannot read trusted local SSH host public keys');
  return { account, home, shell: windows() ? 'powershell' as const : 'posix' as const, platform: windows() ? 'win32' as const : 'linux' as const,
    host: '127.0.0.1' as const, port, hostKeys, authorizedKeys };
}
export async function verifyLoopback(host: string, port: number, hostKeys: string[]) {
  if (!['127.0.0.1', '::1'].includes(host)) throw new Error('Non-loopback SSH target');
  return new Promise<void>((ok, fail) => {
    const client = new Client(); let matched = false;
    const timer = setTimeout(() => { client.destroy(); fail(new Error('SSH host identity check timed out')); }, 10000);
    client.on('error', error => { clearTimeout(timer); if (matched && (error as Error & { level?: string }).level === 'client-authentication') ok(); else fail(error); });
    client.on('ready', () => { clearTimeout(timer); client.end(); matched ? ok() : fail(new Error('SSH identity not checked')); });
    client.connect({ host, port, username: userInfo().username, readyTimeout: 10000, hostVerifier: (key: Buffer) => { matched = hostKeys.includes(key.toString('base64')); return matched; } });
  });
}
function xml(value: string) { return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;'); }
export function loginDefinition(state: State, root: string) {
  const sessionId = state.bootstrap.sessionId, node = join(state.runtime, windows() ? 'node.exe' : 'node'), entry = join(state.runtime, 'client.cjs');
  if (![node, entry, root].every(isAbsolute) || [node, entry, root].some(value => /[\r\n\0]/.test(value))) throw new Error('Unsafe login command');
  if (windows()) {
    const sid = run('whoami.exe', ['/user', '/fo', 'csv', '/nh']).match(/S-1-5-[0-9-]+/)?.[0]; if (!sid) throw new Error('Cannot determine user SID');
    const args = `"${entry}" resume --session ${sessionId}`;
    return { path: join(root, 'login-task.xml'), content: `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${xml(sid)}</UserId></LogonTrigger></Triggers><Principals><Principal id="Target"><UserId>${xml(sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Target"><Exec><Command>${xml(node)}</Command><Arguments>${xml(args)}</Arguments><WorkingDirectory>${xml(state.runtime)}</WorkingDirectory></Exec></Actions></Task>` };
  }
  const quote = (value: string) => '"' + value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('%', '%%').replaceAll('$', '$$') + '"';
  return { path: join(homedir(), '.config', 'systemd', 'user', `nyaarink-${sessionId}.service`), content: `[Unit]\nDescription=NyaaRink authorized assistance ${sessionId}\nAfter=network.target\n[Service]\nType=simple\nExecStart=${quote(node)} ${quote(entry)} resume --session ${sessionId}\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nUMask=0077\n[Install]\nWantedBy=default.target\n` };
}
export function installLogin(state: State, root: string) {
  if (!windows()) run('systemctl', ['--user', 'show-environment']); // Never enable linger or fall back to cron.
  const definition = loginDefinition(state, root); mkdirSync(dirname(definition.path), { recursive: true, mode: 0o700 });
  if (existsSync(definition.path)) {
    const previous = readFileSync(definition.path, windows() ? 'utf16le' : 'utf8').replace(/^\ufeff/, ''); if (previous !== definition.content) throw new Error('Conflicting login definition');
  } else durableWrite(definition.path, windows() ? Buffer.from('\ufeff' + definition.content, 'utf16le') : definition.content);
  privatePath(definition.path);
  if (windows()) run('schtasks.exe', ['/Create', '/TN', `NyaaRink-${state.bootstrap.sessionId}`, '/XML', definition.path, '/F']);
  else { run('systemctl', ['--user', 'daemon-reload']); run('systemctl', ['--user', 'enable', `nyaarink-${state.bootstrap.sessionId}.service`]); }
  return definition.path;
}
export function removeLogin(state: State) {
  if (!state.loginFile) return;
  const hadFile = existsSync(state.loginFile);
  const name = `nyaarink-${state.bootstrap.sessionId}.service`;
  if (windows()) {
    let present = false; try { run('schtasks.exe', ['/Query', '/TN', `NyaaRink-${state.bootstrap.sessionId}`]); present = true; } catch { /* Absent task is already removed. */ }
    if (present) run('schtasks.exe', ['/Delete', '/TN', `NyaaRink-${state.bootstrap.sessionId}`, '/F']);
  } else { try { run('systemctl', ['--user', 'disable', name]); } catch (error) { if (state.loginFile && existsSync(state.loginFile)) throw error; } }
  if (state.loginFile) rmSync(state.loginFile, { force: true });
  if (!windows() && hadFile) run('systemctl', ['--user', 'daemon-reload']);
}
