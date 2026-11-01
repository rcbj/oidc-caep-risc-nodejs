# syntax=docker/dockerfile:1
#
# The demo app's image. The library is compiled in the first stage; the second holds only what runs:
# the compiled library, its runtime dependency and the demo, whose server.ts Node runs as it is.
# The client secret and the listener CA trust chain are NOT in the image: they are mounted at
# /app/demo/generated (docker-compose.yml). The setup script writes them. At start, the entrypoint
# refreshes the chain into the file the configuration's tlsCa names.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:24.22.1-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/oidc-caep-risc-nodejs/package.json packages/oidc-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/oidc-caep-risc-nodejs/tsconfig.json packages/oidc-caep-risc-nodejs/
COPY packages/oidc-caep-risc-nodejs/src packages/oidc-caep-risc-nodejs/src
RUN npm run build -w packages/oidc-caep-risc-nodejs

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/oidc-caep-risc-nodejs/package.json packages/oidc-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/oidc-caep-risc-nodejs/dist packages/oidc-caep-risc-nodejs/dist
COPY demo/server.ts demo/oidc.json demo/
COPY demo/public demo/public
COPY scripts/trust-chain.mjs scripts/trust-chain.mjs
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:3000/healthz >/dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "demo/server.ts"]
