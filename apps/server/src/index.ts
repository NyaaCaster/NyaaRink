import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { BLESSING, VERSION } from '@nyaarink/version';
try {
  const config = loadConfig(process.env);
  const server = createApp().listen(config.PORT, '0.0.0.0', () => console.log(`NyaaRink ${VERSION} | ${BLESSING}`));
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => server.close());
} catch {
  console.error('NyaaRink startup refused: invalid or unavailable private configuration');
  process.exitCode = 1;
}
