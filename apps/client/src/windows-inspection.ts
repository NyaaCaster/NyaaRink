import { randomUUID } from 'node:crypto';

// Only a fixed, read-only system command crosses UAC. The client and its keys
// stay in the original account; anonymous pipe impersonation prevents the
// unelevated receiver from impersonating the administrator.
export function windowsInspectionScript(account: string, port: number) {
  if (!/^[\w.@ -]+$/.test(account) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Unsafe SSH inspection target');
  const pipe = `NyaaRink-inspect-${randomUUID()}`;
  const child = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$pipe=[IO.Pipes.NamedPipeClientStream]::new('.', '${pipe}', [IO.Pipes.PipeDirection]::Out, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Anonymous)
try {
 $pipe.Connect(30000)
 $writer=[IO.StreamWriter]::new($pipe,[Text.UTF8Encoding]::new($false))
 try {
  $sshd=Join-Path ([Environment]::SystemDirectory) 'OpenSSH\\sshd.exe'
  $lines=& $sshd -T -C 'user=${account},host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=${port}' 2>$null
  if($LASTEXITCODE -ne 0){throw 'sshd configuration inspection failed'}
  $config=$lines -join "\n"
  if($config.Length -gt 262144){throw 'sshd configuration too large'}
  $writer.WriteLine((@{ok=$true;config=$config}|ConvertTo-Json -Compress))
 } catch {$writer.WriteLine('{"ok":false}')} finally {$writer.Dispose()}
} finally {$pipe.Dispose()}
`;
  const encoded = Buffer.from(child, 'utf16le').toString('base64');
  return `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$security=[IO.Pipes.PipeSecurity]::new()
$security.SetAccessRuleProtection($true,$false)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($identity in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
 $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($identity,[IO.Pipes.PipeAccessRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
}
$server=[IO.Pipes.NamedPipeServerStream]::new('${pipe}',[IO.Pipes.PipeDirection]::In,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous,4096,4096,$security)
try {
 $pending=$server.BeginWaitForConnection($null,$null)
 $exe=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\\v1.0\\powershell.exe'
 $child=Start-Process -FilePath $exe -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -PassThru
 if(-not $pending.AsyncWaitHandle.WaitOne(30000)){throw 'Administrator inspection connection timed out'}
 $server.EndWaitForConnection($pending)
 $reader=[IO.StreamReader]::new($server,[Text.Encoding]::UTF8)
 try {
  $line=$reader.ReadLine()
  if(-not $line -or $line.Length -gt 524288){throw 'Invalid inspection response'}
  $line
 } finally {$reader.Dispose()}
 if(-not $child.WaitForExit(10000)){throw 'Administrator inspection did not exit'}
} finally {$server.Dispose()}
`;
}
