import { loadConfig } from './config.js';
import { Artifacts } from './artifacts.js';
try {
  const config = loadConfig(process.env);
  new Artifacts(config.CLIENT_ARTIFACT_DIR);
  console.log('NyaaRink private configuration and signed releases verified.');
} catch {
  console.error('NyaaRink preflight refused: private configuration or signed releases unavailable.');
  process.exitCode = 1;
}
