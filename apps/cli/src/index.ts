import { BLESSING, VERSION } from '@nyaarink/version';
if (process.argv.includes('--version')) console.log(`NyaaRink ${VERSION} | ${BLESSING}`);
else { console.error('NyaaRink CLI: operation commands are not implemented yet'); process.exitCode = 2; }
