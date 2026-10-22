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
  filename: z.string().regex(/^nyaarink-client-[0-9.]+-(win32|linux)-x64\.(zip|tar\.gz)$/), sha256: Digest, manifestSha256: Digest,
  runtime: z.literal('go').optional(), executableSha256: Digest.optional() }).strict().refine(item => Boolean(item.runtime) === Boolean(item.executableSha256), 'Native executable hash required');
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
${artifact.runtime === 'go' ? `printf '%s  %s\\n' '${artifact.executableSha256}' "$work/runtime/nyaarink-client" | sha256sum -c -\nchmod 700 "$work/runtime/nyaarink-client"\n"$work/runtime/nyaarink-client" verify --directory "$work/runtime"` : `"$work/runtime/node" "$work/runtime/verify.cjs" "$work/runtime" '${artifact.version}'`}
printf '%s' '${payload}' | base64 -d > "$work/bootstrap.json"
${artifact.runtime === 'go' ? '"$work/runtime/nyaarink-client"' : '"$work/runtime/node" "$work/runtime/client.cjs"'} install --bootstrap "$work/bootstrap.json"
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
    ...(artifact.runtime === 'go' ? [
      `if((Get-FileHash -LiteralPath (Join-Path $runtime 'nyaarink-client.exe') -Algorithm SHA256).Hash.ToLower() -ne '${artifact.executableSha256}'){throw 'Executable SHA256 mismatch'}`,
      "& (Join-Path $runtime 'nyaarink-client.exe') verify --directory $runtime",
    ] : [`& (Join-Path $runtime 'node.exe') (Join-Path $runtime 'verify.cjs') $runtime '${artifact.version}'`]),
    "if($LASTEXITCODE -ne 0){throw 'Release verification failed'}",
    artifact.runtime === 'go' ? "& (Join-Path $runtime 'nyaarink-client.exe') install --bootstrap (Join-Path $root 'bootstrap.json')" : "& (Join-Path $runtime 'node.exe') (Join-Path $runtime 'client.cjs') install --bootstrap (Join-Path $root 'bootstrap.json')",
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
3. ${artifact.runtime === 'go' ? '程序确认当前账户后运行随包便携 sshd，只监听随机回环端口，不安装或改动系统 SSH 服务，不新增防火墙规则。' : '程序检查系统 SSH，经本机确认按需准备服务；系统准备可能请求 UAC，连接仍使用原账户。'}请使用普通账户；高权限账户需额外明确确认。
4. 协助者可能使用 AI Agent。安装后会在用户登录时自动恢复。退出程序、断网或关闭页面均不撤销授权。
5. 结束协助请在页面点击“断开连接”，或在已安装程序执行 disconnect 并确认。删除文件本身不撤销权限。
6. 主动断开后删除本 ZIP、全部解压副本。bootstrap.json 含本次短时凭据，请勿转发或上传扫描平台。过期可回原页面重新下载，不必重新邀请。

client-runtime.zip 是签名发行包（${artifact.runtime === 'go' ? 'Go 原生客户端、微软官方 OpenSSH 必需组件' : '旧版 Node 运行时及客户端'}、清单签名及许可证），${artifact.runtime === 'go' ? '无需预装 Node 或 .NET，' : ''}由启动器自动展开。程序复制到当前用户私密持久目录后，登录恢复不依赖下载目录。原有旧会话继续使用各自运行程序。
${artifact.runtime === 'go' ? 'OpenSSH 固定 10.4.0.0p1-Preview（微软标注非生产就绪），取自 PowerShell/Win32-OpenSSH 官方 OpenSSH-Win64.zip；组件保持原始字节及微软签名，完整 LICENSE 与 NOTICE 随包提供。构建校验固定 ZIP SHA256 及微软发布者，运行前校验发行签名、文件摘要和 Windows Authenticode 信任。维护者需跟踪官方安全更新，审核后发布新版本。' : '旧版发行使用系统 SSH，不自动迁移既有会话。'}
NyaaRink 自有程序没有 Windows Authenticode 签名；发行使用独立 Ed25519 签名。若安全软件告警，请保留防护并向协助方报告，不添加排除或关闭防护。
Nyaa be with you.
`;
  // Store the already compressed release unchanged; no server-side extraction or secret files.
  const data = zipSync({ 'start.bat': Buffer.from(windowsLauncher(artifact)), 'bootstrap.json': Buffer.from(JSON.stringify(boot)),
    'client-runtime.zip': archive, 'README.txt': Buffer.from('\uFEFF' + readme) }, { level: 0 });
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}
