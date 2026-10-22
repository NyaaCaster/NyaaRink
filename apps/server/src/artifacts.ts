import { readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
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
  constructor(readonly directory: string, publicKey = RELEASE_PUBLIC_KEY) {
    const text = readFileSync(join(directory, 'index.json')); if (text.length > 8192) throw new Error('Invalid release catalog');
    if (!verify(null, text, createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' }), readFileSync(join(directory, 'index.sig')))) throw new Error('Release catalog signature invalid');
    this.items = Catalog.parse(JSON.parse(text.toString())).artifacts;
    if (new Set(this.items.map(item => item.platform)).size !== 2) throw new Error('Incomplete platform catalog');
    for (const item of this.items) {
      const path = join(directory, item.filename), stat = lstatSync(path);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 150 * 1024 * 1024 || createHash('sha256').update(readFileSync(path)).digest('hex') !== item.sha256) throw new Error('Release artifact hash invalid');
    }
  }
  get(platform: 'win32' | 'linux') { return this.items.find(item => item.platform === platform)!; }
}
export function connectionScript(input: unknown, artifact: ClientArtifact) {
  const boot = Bootstrap.parse(input);
  const url = `${boot.origin}/downloads/${artifact.filename}`;
  const payload = Buffer.from(JSON.stringify(boot)).toString('base64');
  if (artifact.platform === 'win32') {
    const ps = `$ErrorActionPreference='Stop'
$dir=Join-Path $env:LOCALAPPDATA ('NyaaRink-bootstrap-'+[guid]::NewGuid())
$null=New-Item -ItemType Directory -Path $dir
try {
 $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $acl=[System.Security.AccessControl.DirectorySecurity]::new()
 $acl.SetSecurityDescriptorSddlForm(('O:'+ $sid +'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)'),[System.Security.AccessControl.AccessControlSections]::Access)
 [IO.Directory]::SetAccessControl($dir,$acl)
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 Invoke-WebRequest -UseBasicParsing -Uri '${url}' -OutFile (Join-Path $dir 'package.zip') -MaximumRedirection 0
 if((Get-FileHash (Join-Path $dir 'package.zip') -Algorithm SHA256).Hash.ToLower() -ne '${artifact.sha256}'){throw 'Package SHA256 mismatch'}
 $runtime=Join-Path $dir 'runtime'
 Expand-Archive -LiteralPath (Join-Path $dir 'package.zip') -DestinationPath $runtime
 if((Get-FileHash (Join-Path $runtime 'manifest.json') -Algorithm SHA256).Hash.ToLower() -ne '${artifact.manifestSha256}'){throw 'Manifest SHA256 mismatch'}
 & (Join-Path $runtime 'node.exe') (Join-Path $runtime 'verify.cjs') $runtime '${artifact.version}'
 if($LASTEXITCODE -ne 0){throw 'Release verification failed'}
 $bootstrap=Join-Path $dir 'bootstrap.json'
 [IO.File]::WriteAllBytes($bootstrap,[Convert]::FromBase64String('${payload}'))
 & (Join-Path $runtime 'node.exe') (Join-Path $runtime 'client.cjs') install --bootstrap $bootstrap
 if($LASTEXITCODE -ne 0){throw 'Installation incomplete; authorization retained'}
} finally {if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force}}
`;
    return '@echo off\r\necho NyaaRink - SSH assistance may include AI Agents.\r\npowershell.exe -NoProfile -EncodedCommand ' + Buffer.from(ps, 'utf16le').toString('base64') + '\r\nif errorlevel 1 echo Setup incomplete. Review the error above.\r\npause\r\n';
  }
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
