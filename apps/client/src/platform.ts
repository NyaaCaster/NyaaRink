import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readlinkSync, rmSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { userInfo, homedir } from 'node:os';
import { Client, utils } from 'ssh2';
import { durableWrite } from '../../server/src/crypto.js';
import type { State } from './state.js';
import { privatePath } from './state.js';
import { windowsEnvironment } from './windows.js';
import { windowsInspectionScript } from './windows-inspection.js';
export type Confirm = (text: string) => Promise<boolean>;
export function run(command: string, args: string[], env?: NodeJS.ProcessEnv) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, timeout: 60000, env: env ?? process.env }).trim();
}
export const windows = () => process.platform === 'win32';
export function powershell(script: string, env?: NodeJS.ProcessEnv) { return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop";' + script], windowsEnvironment(env)); }
export function sshVersion(text: string) {
  return /OpenSSH(?:_for_Windows)?_\d+\.\d+(?:p\d+)?/.exec(text)?.[0];
}
export function inspectSshVersion() {
  const result = spawnSync(sshdExecutable(), ['-?'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  const version = sshVersion((result.stdout ?? '') + (result.stderr ?? ''));
  if (result.error || !version) throw new Error('无法识别本机OpenSSH服务版本；不自动替换或升级已有服务');
  return version;
}
export function matchesWindowsService(command: string, executable: string) {
  // Custom binaries and command-line configuration overrides need a separate
  // audited adapter; never inspect a different daemon than the running service.
  const path = command.trim().replace(/^"([^"\r\n]+)"$/, '$1');
  return path.toLowerCase() === executable.toLowerCase();
}
export async function inspectServiceIdentity(confirm?: Confirm) {
  if (!windows()) {
    const unit = run('systemctl', ['show', 'ssh.service', '--property=ExecStart,Environment,EnvironmentFiles,MainPID']);
    const defaults = existsSync('/etc/default/ssh') ? readFileSync('/etc/default/ssh', 'utf8') : '';
    requireLinuxService(unit, defaults);
    if (confirm) {
      const pid = /^MainPID=([1-9][0-9]*)$/m.exec(unit)?.[1];
      if (!pid) throw new Error('SSH服务没有有效主进程；未授权上线');
      const proc = '/proc/' + pid + '/exe';
      let executable: string;
      try { executable = readlinkSync(proc); }
      catch {
        if (!await confirm('需要本地sudo只读核验运行中sshd的实际程序路径，不更改服务或目标账户。是否继续？')) throw new Error('SSH运行程序检查未获确认；授权保留等待');
        const result = spawnSync('sudo', ['--', '/usr/bin/readlink', '-e', proc], { stdio: ['inherit', 'pipe', 'pipe'], encoding: 'utf8', timeout: 60000 });
        if (result.status !== 0) throw new Error('无法核验运行中的SSH程序；授权保留等待');
        executable = result.stdout.trim();
      }
      requireLinuxRuntime(pid, executable, run('systemctl', ['show', 'ssh.service', '--property=MainPID', '--value']));
    }
    return;
  }
  const command = powershell('$s=Get-CimInstance Win32_Service -Filter "Name=\'sshd\'"; if($s){$s.PathName}');
  if (!matchesWindowsService(command, sshdExecutable())) throw new Error('SSH服务程序或启动参数不属于当前支持的系统组件；未修改服务，请由C端确认配置');
}
export function requireLinuxRuntime(pid: string, executable: string, currentPid: string) {
  if (!/^[1-9][0-9]*$/.test(pid) || currentPid.trim() !== pid || executable !== '/usr/sbin/sshd') throw new Error('SSH运行程序发生变化或与系统服务不符；请重试，未授权上线');
}
export function requireLinuxService(unit: string, defaults: string) {
  const properties = new Map(unit.split(/\r?\n/).map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
  const start = properties.get('ExecStart') ?? '';
  // Only the distribution unit with empty SSHD_OPTS is supported. Never parse
  // shell syntax or inspect default configuration for a daemon using -f/-o.
  if (!/^\{ path=\/usr\/sbin\/sshd ; argv\[\]=\/usr\/sbin\/sshd -D(?: \$SSHD_OPTS)? ;[^{}]*\}$/.test(start.trim()) ||
      !/^(?:|SSHD_OPTS=|"SSHD_OPTS=")$/.test(properties.get('Environment') ?? '') ||
      !/^(?:|\/etc\/default\/ssh \(ignore_errors=yes\))$/.test(properties.get('EnvironmentFiles') ?? '')) {
    throw new Error('SSH systemd服务程序或参数不受支持；未修改现有服务');
  }
  for (const line of defaults.split(/\r?\n/).map(value => value.trim()).filter(value => value && !value.startsWith('#'))) {
    if (!/^SSHD_OPTS=(?:|''|"")(?:\s+#.*)?$/.test(line)) throw new Error('SSH环境文件包含自定义启动参数；未修改现有配置');
  }
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
  const status = serviceStatus();
  if (status !== 'missing') { await inspectServiceIdentity(); inspectSshVersion(); }
  if (status === 'running') return;
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
  await inspectServiceIdentity(confirm);
  console.log(`SSH服务：${inspectSshVersion()}；版本识别不代表安全补丁或兼容验收通过`);
  const account = userInfo().username, home = homedir();
  if (!/^[\w.@ -]+$/.test(account)) throw new Error('Unsupported local account name');
  const args = ['-T', '-C', `user=${account},host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=${port}`];
  let text: string;
  try { text = inspectConfig(args.slice(1), arguments_ => run(sshdExecutable(), arguments_)); }
  catch (error) {
    if (windows()) {
      if (!await confirm('需要通过Windows UAC以管理员权限只读检查sshd配置；SSH仍授权原账户，不返回主机私钥，不更改配置。是否继续？')) throw new Error('SSH配置检查提权未获确认；授权保留等待');
      let result: unknown;
      try { result = JSON.parse(powershell(windowsInspectionScript(account, port))); }
      catch { throw new Error('SSH配置检查失败或UAC被拒绝；未改变目标账户，授权保留等待'); }
      if (!result || typeof result !== 'object' || !('ok' in result) || result.ok !== true || !('config' in result) || typeof result.config !== 'string' || result.config.length > 262144) throw new Error('管理员只读SSH配置检查失败；授权保留等待');
      text = result.config;
    } else {
      if (!await confirm('需要本地sudo只读检查目标账户的有效sshd配置，不更改账户、不上传私钥。是否继续？')) throw error;
      const result = spawnSync('sudo', ['--', sshdExecutable(), ...args], { stdio: ['inherit', 'pipe', 'pipe'], encoding: 'utf8' });
      if (result.status !== 0) throw new Error('无法检查有效SSH配置；授权保留等待'); text = result.stdout;
    }
  }
  const options = new Map(text.split(/\r?\n/).map(line => { const at = line.indexOf(' '); return [line.slice(0, at), line.slice(at + 1)] as const; }));
  if (options.get('pubkeyauthentication') !== 'yes' || options.get('authorizedkeyscommand') !== 'none') throw new Error('SSH public-key configuration unsupported; no global settings changed');
  requireSshCapabilities(text, port);
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
export function requireSshCapabilities(text: string, port: number) {
  const lines = text.split(/\r?\n/);
  const value = (name: string) => lines.find(line => line.startsWith(name + ' '))?.slice(name.length + 1);
  const algorithms = value('pubkeyacceptedalgorithms') ?? value('pubkeyacceptedkeytypes');
  if (!algorithms?.split(',').includes('ssh-ed25519') || value('permittty') !== 'yes' ||
      !lines.some(line => /^subsystem sftp\s+\S/.test(line)) || !lines.includes(`port ${port}`)) {
    throw new Error('SSH缺少Ed25519认证、PTY、SFTP或选定监听端口；未放宽限制或升级服务');
  }
}
// -G parses Match configuration without testing host private keys. Older
// daemons may not implement it; -T remains the safe, read-only fallback.
export function inspectConfig(context: string[], execute: (args: string[]) => string) {
  try { return execute(['-G', ...context]); }
  catch { return execute(['-T', ...context]); }
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
export function loginDefinition(state: State, root: string, mode: 'access' | 'cleanup' = 'access') {
  const sessionId = state.bootstrap.sessionId, node = join(state.runtime, windows() ? 'node.exe' : 'node'), entry = join(state.runtime, 'client.cjs');
  const command = mode === 'cleanup' ? 'cleanup' : 'resume', suffix = mode === 'cleanup' ? '-cleanup' : '';
  if (![node, entry, root].every(isAbsolute) || [node, entry, root].some(value => /[\r\n\0]/.test(value))) throw new Error('Unsafe login command');
  if (windows()) {
    const sid = run('whoami.exe', ['/user', '/fo', 'csv', '/nh']).match(/S-1-5-[0-9-]+/)?.[0]; if (!sid) throw new Error('Cannot determine user SID');
    const args = `"${entry}" ${command} --session ${sessionId}`;
    return { path: join(root, `login-task${suffix}.xml`), content: `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${xml(sid)}</UserId></LogonTrigger></Triggers><Principals><Principal id="Target"><UserId>${xml(sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Target"><Exec><Command>${xml(node)}</Command><Arguments>${xml(args)}</Arguments><WorkingDirectory>${xml(state.runtime)}</WorkingDirectory></Exec></Actions></Task>` };
  }
  const quote = (value: string) => '"' + value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('%', '%%').replaceAll('$', '$$') + '"';
  return { path: join(homedir(), '.config', 'systemd', 'user', `nyaarink-${sessionId}${suffix}.service`), content: `[Unit]\nDescription=NyaaRink ${command} ${sessionId}\nAfter=network.target\n[Service]\nType=simple\nExecStart=${quote(node)} ${quote(entry)} ${command} --session ${sessionId}\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nUMask=0077\n[Install]\nWantedBy=default.target\n` };
}
export function installLogin(state: State, root: string, mode: 'access' | 'cleanup' = 'access') {
  if (!windows()) run('systemctl', ['--user', 'show-environment']); // Never enable linger or fall back to cron.
  const definition = loginDefinition(state, root, mode), suffix = mode === 'cleanup' ? '-cleanup' : ''; mkdirSync(dirname(definition.path), { recursive: true, mode: 0o700 });
  if (existsSync(definition.path)) {
    const previous = readFileSync(definition.path, windows() ? 'utf16le' : 'utf8').replace(/^\ufeff/, ''); if (previous !== definition.content) throw new Error('Conflicting login definition');
  } else durableWrite(definition.path, windows() ? Buffer.from('\ufeff' + definition.content, 'utf16le') : definition.content);
  privatePath(definition.path);
  if (windows()) run('schtasks.exe', ['/Create', '/TN', `NyaaRink-${state.bootstrap.sessionId}${suffix}`, '/XML', definition.path, '/F']);
  else { run('systemctl', ['--user', 'daemon-reload']); run('systemctl', ['--user', 'enable', `nyaarink-${state.bootstrap.sessionId}${suffix}.service`]); }
  return definition.path;
}
export function removeLogin(state: State, mode: 'access' | 'cleanup' = 'access') {
  const file = mode === 'cleanup' ? state.cleanupLoginFile : state.loginFile, suffix = mode === 'cleanup' ? '-cleanup' : '';
  if (!file) return;
  const hadFile = existsSync(file);
  const name = `nyaarink-${state.bootstrap.sessionId}${suffix}.service`;
  if (windows()) {
    // COM returns null for absence; access/query errors must propagate rather
    // than being mistaken for a task that was successfully removed.
    powershell(`$s=New-Object -ComObject 'Schedule.Service';$s.Connect();$f=$s.GetFolder('\\');$name='NyaaRink-${state.bootstrap.sessionId}${suffix}';$t=@($f.GetTasks(0)|Where-Object {$_.Name -eq $name});if($t.Count){$f.DeleteTask($name,0)}`);
  } else { try { run('systemctl', ['--user', 'disable', name]); } catch (error) { if (existsSync(file)) throw error; } }
  rmSync(file, { force: true });
  if (!windows() && hadFile) run('systemctl', ['--user', 'daemon-reload']);
}
