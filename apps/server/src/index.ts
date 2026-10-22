import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { BLESSING, VERSION } from '@nyaarink/version';
import { Authority } from './authority.js';
import { RinkService } from './service.js';
import { Artifacts } from './artifacts.js';
import { TunnelHub } from './tunnel.js';
import { NativeSSH } from './proxy.js';
import { fileURLToPath } from 'node:url';
import { Operations } from './operations.js';
import { Files } from './files.js';
import { Shells } from './shells.js';
import { authorized } from './management.js';
import { BrowserEvents } from './events.js';
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
    const hub = service ? new TunnelHub(service) : undefined;
    const native = hub ? new NativeSSH(hub, config.RUNTIME_DIR, fileURLToPath(new URL('./proxy-client.js', import.meta.url))) : undefined;
    const operations = hub ? new Operations(hub) : undefined;
    const files = hub ? new Files(hub) : undefined;
    const shells = hub ? new Shells(hub, req => authorized(req, config)) : undefined;
    const events = service ? new BrowserEvents(service, config.masterKey) : undefined;
    let accepting = false;
    const server = createApp(service, config, artifacts, native, operations, files, shells, () => accepting).listen(config.PORT, '0.0.0.0', () => console.log(`NyaaRink ${VERSION} | ${BLESSING}${authority.frozen ? ' | frozen' : ''}`));
    hub?.attach(server);
    shells?.attach(server);
    events?.attach(server);
    accepting = true;
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => {
      accepting = false;
      const stopped = operations?.close(); const flushed = hub?.close();
      shells?.close();
      events?.close();
      native?.close();
      server.close(() => { void Promise.all([stopped, flushed]).then(() => { if (service) return service.close(); authority.close(); }); });
    });
  }
} catch {
  console.error('NyaaRink startup refused: invalid or unavailable private configuration');
  process.exitCode = 1;
}
