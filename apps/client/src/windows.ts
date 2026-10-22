import { join } from 'node:path';

// Windows PowerShell 5.1 must not autoload PowerShell 7 module/type data.
export function windowsEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...env, PSModulePath: join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') };
}
