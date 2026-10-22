import { BLESSING, VERSION } from '@nyaarink/version';
if (process.argv.includes('--version')) console.log(`NyaaRink client ${VERSION} | ${BLESSING}`);
else { console.error('NyaaRink client: installation is not implemented yet'); process.exitCode = 2; }
