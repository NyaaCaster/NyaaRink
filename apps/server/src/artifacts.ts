import { readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import { zipSync } from 'fflate';
import { VERSION } from '@nyaarink/version';
import { RELEASE_PUBLIC_KEY } from '../../client/src/release-key.js';
import { Bootstrap } from '../../../packages/contracts/device.js';

const Digest = z.string().regex(/^[a-f0-9]{64}$/);
const Artifact = z.object({ platform: z.enum(['win32', 'linux']), arch: z.literal('x64'), version: z.literal(VERSION),
  filename: z.string().regex(/^nyaarink-client-[0-9.]+-(win32|linux)-x64\.(zip|tar\.gz)$/), sha256: Digest, manifestSha256: Digest }).strict();
const Catalog = z.object({ v: z.literal(1), version: z.literal(VERSION), artifacts: z.array(Artifact).length(2) }).strict();
export type ClientArtifact = z.infer<typeof Artifact>;
export class Artifacts {
  readonly items: ClientArtifact[];
  private readonly windowsArchive: Buffer;
  constructor(readonly directory: string, publicKey = RELEASE_PUBLIC_KEY) {
    const text = readFileSync(join(directory, 'index.json')); if (text.length > 8192) throw new Error('Invalid release catalog');
    if (!verify(null, text, createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' }), readFileSync(join(directory, 'index.sig')))) throw new Error('Release catalog signature invalid');
    this.items = Catalog.parse(JSON.parse(text.toString())).artifacts;
    if (new Set(this.items.map(item => item.platform)).size !== 2) throw new Error('Incomplete platform catalog');
    for (const item of this.items) {
      const path = join(directory, item.filename), stat = lstatSync(path);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 150 * 1024 * 1024 || createHash('sha256').update(readFileSync(path)).digest('hex') !== item.sha256) throw new Error('Release artifact hash invalid');
    }
    this.windowsArchive = readFileSync(join(directory, this.get('win32').filename));
    if (createHash('sha256').update(this.windowsArchive).digest('hex') !== this.get('win32').sha256) throw new Error('Release artifact changed');
  }
  windowsPackage(input: unknown) { return windowsConnectionPackage(input, this.get('win32'), this.windowsArchive); }
  get(platform: 'win32' | 'linux') { return this.items.find(item => item.platform === platform)!; }
}
export function connectionScript(input: unknown, artifact: ClientArtifact) {
  const boot = Bootstrap.parse(input);
  const url = `${boot.origin}/downloads/${artifact.filename}`;
  const payload = Buffer.from(JSON.stringify(boot)).toString('base64');
  if (artifact.platform === 'win32') return windowsLauncher(artifact);
  return `#!/bin/sh
set -eu
umask 077
printf '%s\\n' 'NyaaRink: SSH assistance may include AI Agents. Network loss does not revoke access.'
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
curl --fail --show-error --silent --proto '=https' --tlsv1.2 --max-redirs 0 '${url}' -o "$work/package.tar.gz"
printf '%s  %s\\n' '${artifact.sha256}' "$work/package.tar.gz" | sha256sum -c -
mkdir "$work/runtime"
tar -xzf "$work/package.tar.gz" -C "$work/runtime" --no-same-owner
printf '%s  %s\\n' '${artifact.manifestSha256}' "$work/runtime/manifest.json" | sha256sum -c -
"$work/runtime/node" "$work/runtime/verify.cjs" "$work/runtime" '${artifact.version}'
printf '%s' '${payload}' | base64 -d > "$work/bootstrap.json"
"$work/runtime/node" "$work/runtime/client.cjs" install --bootstrap "$work/bootstrap.json"
`;
}

export function windowsLauncher(artifact: ClientArtifact) {
  // Paths come from environment variables, never interpolated into PowerShell source.
  const commands = [
    "$ErrorActionPreference='Stop'",
    "$env:PSModulePath=Join-Path $PSHOME 'Modules'",
    "$root=$env:NR_PACKAGE_ROOT",
    "$dir=Join-Path $env:LOCALAPPDATA ('NyaaRink-bootstrap-'+[guid]::NewGuid())",
    "$null=New-Item -ItemType Directory -Path $dir",
    "try { $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$acl=[Security.AccessControl.DirectorySecurity]::new()",
    "$acl.SetSecurityDescriptorSddlForm(('D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)'),[Security.AccessControl.AccessControlSections]::Access)",
    "[IO.Directory]::SetAccessControl($dir,$acl)",
    `if((Get-FileHash -LiteralPath (Join-Path $root 'client-runtime.zip') -Algorithm SHA256).Hash.ToLower() -ne '${artifact.sha256}'){throw 'Package SHA256 mismatch'}`,
    "$runtime=Join-Path $dir 'runtime'",
    "Expand-Archive -LiteralPath (Join-Path $root 'client-runtime.zip') -DestinationPath $runtime",
    `if((Get-FileHash -LiteralPath (Join-Path $runtime 'manifest.json') -Algorithm SHA256).Hash.ToLower() -ne '${artifact.manifestSha256}'){throw 'Manifest SHA256 mismatch'}`,
    `& (Join-Path $runtime 'node.exe') (Join-Path $runtime 'verify.cjs') $runtime '${artifact.version}'`,
    "if($LASTEXITCODE -ne 0){throw 'Release verification failed'}",
    "& (Join-Path $runtime 'node.exe') (Join-Path $runtime 'client.cjs') install --bootstrap (Join-Path $root 'bootstrap.json')",
    "if($LASTEXITCODE -ne 0){throw 'Installation incomplete; authorization retained'}",
    "} finally {if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force}}",
  ].join('; ');
  return '@echo off\r\nsetlocal DisableDelayedExpansion\r\necho NyaaRink - SSH assistance may include AI Agents.\r\necho Read README.txt. Network loss does not revoke authorization.\r\nset "NR_PACKAGE_ROOT=%~dp0"\r\n' +
    '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -Command "' + commands + '"\r\n' +
    'set "NR_RESULT=%ERRORLEVEL%"\r\nif not "%NR_RESULT%"=="0" echo Setup incomplete. Review the error above. Authorization is retained.\r\npause\r\nexit /b %NR_RESULT%\r\n';
}
export function windowsConnectionPackage(input: unknown, artifact: ClientArtifact, archive: Buffer) {
  const boot = Bootstrap.parse(input);
  if (artifact.platform !== 'win32' || archive.length > 150 * 1024 * 1024 || createHash('sha256').update(archive).digest('hex') !== artifact.sha256) throw new Error('Release artifact hash invalid');
  const readme = `NyaaRink - Windows 连接包 / Windows connection package

1. 解压整个连接包到自己的本地目录，先阅读 start.bat，再双击运行。
2. start.bat 通过明文 PowerShell 在本地校验并展开随包 client-runtime.zip；不下载程序，不修改执行策略。随后运行发行验签与安装。
3. 程序确认原账户，检测 SSH 服务，经你确认按需安装/启动；仅系统准备与检查请求 UAC。SSH 默认使用普通账户。
4. 协助者可能使用 AI Agent。安装后会在用户登录时自动恢复。退出程序、断网或关闭页面均不撤销授权。
5. 结束协助请在页面点击“断开连接”，或在已安装程序执行 disconnect 并确认。删除文件本身不撤销权限。
6. 主动断开后删除本 ZIP、全部解压副本。bootstrap.json 含本次短时凭据，请勿转发或上传扫描平台。过期可回原页面重新下载，不必重新邀请。

client-runtime.zip 是原始签名发行包（Node、客户端、清单签名及许可证），由启动器自动展开，无需手动二次解压。运行时复制到当前用户私密持久目录后，登录恢复不依赖此下载目录。
本包不是 Windows Authenticode 签名安装器。内部系统准备/检查仍使用 PowerShell；如安全软件告警，请保留防护并向协助方报告，不添加排除或关闭防护。
Nyaa be with you.
`;
  // Store the already compressed release unchanged; no server-side extraction or secret files.
  const data = zipSync({ 'start.bat': Buffer.from(windowsLauncher(artifact)), 'bootstrap.json': Buffer.from(JSON.stringify(boot)),
    'client-runtime.zip': archive, 'README.txt': Buffer.from('\uFEFF' + readme) }, { level: 0 });
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}
