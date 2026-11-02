# syntax=docker/dockerfile:1
#
# The demo app's image. The library is compiled in the first stage. The test stage runs the unit
# suite and is not the default target, so `docker build .` still produces the demo. The last stage
# holds only what runs: the compiled library, its runtime dependency and the demo, whose server.ts
# Node runs as it is. It also has the registrar, which a live sign-in runs with the image entrypoint.
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

# The unit suite. `docker build --target test .` runs it. The demo stage does not depend on it.
FROM build AS test
RUN apk add --no-cache openssl
COPY packages/oidc-caep-risc-nodejs/test packages/oidc-caep-risc-nodejs/test
COPY scripts scripts
COPY VERSION VERSION
RUN npm test

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/oidc-caep-risc-nodejs/package.json packages/oidc-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/oidc-caep-risc-nodejs/dist packages/oidc-caep-risc-nodejs/dist
# configure-iya-sts.ts imports the library source; Node runs that file as it is.
COPY packages/oidc-caep-risc-nodejs/src packages/oidc-caep-risc-nodejs/src
COPY demo/server.ts demo/oidc.json demo/
COPY demo/public demo/public
COPY scripts/trust-chain.mjs scripts/redirects.mjs scripts/configure-iya-sts.ts scripts/
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER node
EXPOSE 3000
# PORT defaults to 3000 so a run that does not set it (the CI demo job) is still healthy.
# Compose passes PORT and overrides this. The shell form expands it; EXPOSE does not, so it stays 3000.
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "demo/server.ts"]
