import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { BLESSING, VERSION } from '@nyaarink/version';
import { Authority } from './authority.js';
import { RinkService } from './service.js';
import { Artifacts } from './artifacts.js';
try {
  const config = loadConfig(process.env);
  if (process.argv.includes('--initialize-authority')) {
    Authority.initialize(config.AUTHORITY_DIR, config.masterKey);
    console.log('NyaaRink authority initialized; keep its latest copy separate from database backups.');
  } else {
    const authority = new Authority(config.AUTHORITY_DIR, config.masterKey);
    let service: RinkService | undefined;
    try { if (!authority.frozen) service = await RinkService.open(authority, config.STATE_DIR, config.PUBLIC_BASE_URL); }
    catch { authority.freeze('SERVICE_INITIALIZATION_FAILED'); }
    const artifacts = new Artifacts(config.CLIENT_ARTIFACT_DIR);
    const server = createApp(service, config, artifacts).listen(config.PORT, '0.0.0.0', () => console.log(`NyaaRink ${VERSION} | ${BLESSING}${authority.frozen ? ' | frozen' : ''}`));
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => {
      server.close(() => { if (service) void service.close(); else authority.close(); });
    });
  }
} catch {
  console.error('NyaaRink startup refused: invalid or unavailable private configuration');
  process.exitCode = 1;
}
