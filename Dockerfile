# syntax=docker/dockerfile:1
#
# The demo app's image. The library is compiled in the first stage. The test stage runs the unit
# suite and is not the default target, so `docker build .` still produces the demo. The last stage
# holds only what runs: the compiled library, its runtime dependency and the demo, whose server.ts
# Node runs as it is. It also has the registrar, which a live sign-in runs with the image entrypoint.
# The listener CA trust chain IS in the image: tlsCa's file, demo/generated/idp-ca.pem, which the
# install script (scripts/configure-iya-sts.ts) wrote before the build. The client secret is NOT:
# it is mounted at /app/demo/generated (docker-compose.yml). At start, the entrypoint refreshes the
# chain into the file tlsCa names, unless TLS_CA_REFRESH=0.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:26.13.0-alpine AS build
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
COPY demo/oidc.json demo/oidc.json
# scripts/demo-errors.test.ts starts the demo server itself.
COPY demo/server.ts demo/server.ts
COPY demo/public demo/public
RUN npm test

FROM node:26.13.0-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/oidc-caep-risc-nodejs/package.json packages/oidc-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/oidc-caep-risc-nodejs/dist packages/oidc-caep-risc-nodejs/dist
# configure-iya-sts.ts imports the library source; Node runs that file as it is.
COPY packages/oidc-caep-risc-nodejs/src packages/oidc-caep-risc-nodejs/src
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts listener CA trust
# chain scripts/configure-iya-sts.ts saved. The image trusts that iya-sts with no bind mount and no
# fetch. Rebuild after running the install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client secret or a key), and
# keeps out node_modules. A COPY of the demo DIRECTORY succeeds with or without the chain, so a
# fresh clone and CI still build; naming the file, or a glob that matches nothing, fails the build
# in both builders.
COPY demo demo
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
