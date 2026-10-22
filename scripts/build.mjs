import { build } from 'esbuild';
import { build as viteBuild } from 'vite';
for (const name of ['server', 'cli']) {
  await build({ entryPoints: [`apps/${name}/src/index.ts`], outfile: `dist/${name}/index.js`,
    bundle: true, platform: 'node', target: 'node24', format: 'esm', sourcemap: true,
    external: ['better-sqlite3', 'ssh2'], banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" } });
}
for (const name of ['index', 'verify']) {
  await build({ entryPoints: [`apps/client/src/${name}.ts`], outfile: `dist/client/${name === 'index' ? 'client' : name}.cjs`,
    bundle: true, platform: 'node', target: 'node24', format: 'cjs', sourcemap: false,
    external: ['cpu-features', '*.node'] });
}
for (const entry of ['maintenance', 'preflight', 'container-entry']) await build({ entryPoints: [`apps/server/src/${entry}.ts`], outfile: `dist/server/${entry}.js`, bundle: true, platform: 'node', target: 'node24', format: 'esm', external: ['better-sqlite3', 'ssh2'], banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" } });
await viteBuild({ configFile: 'apps/web/vite.config.ts' });
await build({ entryPoints: ['apps/server/src/proxy-client.ts'], outfile: 'dist/server/proxy-client.js', bundle: true, platform: 'node', target: 'node24', format: 'esm' });
await import('./licenses.mjs');
