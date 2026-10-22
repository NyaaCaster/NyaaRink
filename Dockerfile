# syntax=docker/dockerfile:1
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/cli/package.json apps/cli/package.json
COPY apps/client/package.json apps/client/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/version/package.json packages/version/package.json
RUN --mount=type=cache,target=/root/.npm npm_config_nodedir=/usr/local npm ci --no-fund
COPY . .
RUN npm run typecheck && npm run build && npm prune --omit=dev

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/LICENSE /app/THIRD-PARTY-NOTICES.md ./
USER node
RUN node --input-type=module -e "import Database from 'better-sqlite3'; import ssh2 from 'ssh2'; const db = new Database(':memory:'); if (db.prepare('SELECT 1 AS value').get().value !== 1 || !ssh2.utils.generateKeyPairSync('ed25519', {}).public) process.exit(1); db.close();" && ssh -V
RUN node --input-type=module -e "import { spawnSync } from 'node:child_process'; const r = spawnSync(process.execPath, ['dist/server/index.js'], { env: {}, encoding: 'utf8' }); if (r.status !== 1 || r.stderr.trim() !== 'NyaaRink startup refused: invalid or unavailable private configuration') { console.error(r.stderr); process.exit(1); }" && node dist/cli/index.js --version
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/server/index.js"]

FROM nginxinc/nginx-unprivileged:1.28-alpine@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8 AS gateway
COPY nginx/nginx.conf /etc/nginx/nginx.conf
USER 101:101
ENTRYPOINT ["nginx", "-g", "daemon off;"]
