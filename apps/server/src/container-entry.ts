// The image entrypoint holds the kernel flock for this entire process lifetime.
// Unlike PID files, the lock survives PID namespace changes and releases on crash.
import { rmSync } from 'node:fs';
import { join } from 'node:path';
if (!process.env.AUTHORITY_DIR) throw new Error('Missing authority directory');
rmSync(join(process.env.AUTHORITY_DIR, 'writer.lock'), { force: true });
await import('./index.js');
