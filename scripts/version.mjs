import { readFileSync, writeFileSync } from 'node:fs';
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
writeFileSync(new URL('../packages/version/generated.ts', import.meta.url), `export const VERSION = ${JSON.stringify(version)} as const;\n`);
