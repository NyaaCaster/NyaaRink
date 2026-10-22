import { verifyRelease } from './release.js';
try {
  const [, , directory, version] = process.argv;
  if (!directory || !version) throw new Error('Usage: verify <directory> <expectedVersion>');
  verifyRelease(directory, version); console.log('NyaaRink release signature and files verified');
} catch (error) { console.error(error instanceof Error ? error.message : 'Verification failed'); process.exitCode = 1; }
