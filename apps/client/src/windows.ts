import { join } from 'node:path';

// Windows PowerShell 5.1 must not autoload PowerShell 7 module/type data.
export function windowsEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  // Plain copies (including test-runner environments) can contain differently
  // cased duplicate keys. Windows spawn keeps only one of those keys.
  const entries = Object.entries(env);
  const clean = Object.fromEntries(entries.filter(([key]) => key.toLowerCase() !== 'psmodulepath'));
  const systemRoot = entries.find(([key]) => key.toLowerCase() === 'systemroot')?.[1] ?? 'C:\\Windows';
  return { ...clean, PSModulePath: join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') };
}
