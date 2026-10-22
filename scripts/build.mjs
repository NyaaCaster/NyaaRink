import { build } from 'esbuild';
import { build as viteBuild } from 'vite';
for (const name of ['server', 'cli', 'client']) {
  await build({ entryPoints: [`apps/${name}/src/index.ts`], outfile: `dist/${name}/index.js`,
    bundle: true, platform: 'node', target: 'node24', format: 'esm', sourcemap: true,
    external: ['better-sqlite3', 'ssh2'], banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" } });
}
await viteBuild({ configFile: 'apps/web/vite.config.ts' });
