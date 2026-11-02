# oidc-caep-risc-nodejs

A **confidential OpenID Connect client** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a traditional web demo built on it. It runs the Authorization Code flow with PKCE, authenticates at the token endpoint (`client_secret_basic`, `client_secret_post`, or `private_key_jwt`), and receives CAEP and RISC events on one Shared Signals poll stream. It depends on [`jose`](https://github.com/panva/jose) only. CAEP and RISC are on by default. `signals: false` turns them off, drops `ssf.read` and `ssf.manage`, and does not contact a transmitter.

The configuration names the same discovery URL and the same scopes as [`oidc-caep-client`](https://github.com/rcbj/oidc-caep-client). That project is a browser application and a public client. This one is a server, and the client is confidential.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/).

**Documentation:** <https://rcbj.github.io/oidc-caep-risc-nodejs/>

| Path | |
|---|---|
| [`packages/oidc-caep-risc-nodejs`](packages/oidc-caep-risc-nodejs) | The library, published to npm as [`oidc-caep-risc-nodejs`](https://www.npmjs.com/package/oidc-caep-risc-nodejs). |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | Registers the confidential client on a running iya-sts and creates a test user. |

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).

## Install

```sh
npm install oidc-caep-risc-nodejs
```

See the [package README](packages/oidc-caep-risc-nodejs/README.md) for the reference and the [server-side guide](packages/oidc-caep-risc-nodejs/docs/guide.md) for a walkthrough.

## Run the demo

```sh
npm install
ADMIN_API_CLIENT_SECRET=… OIDC_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `oidc-demo-user`. Unless `OIDC_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/oidc-demo-user.password` (created mode 0600) and prints only that path, never the password. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## Develop

```sh
npm install
npm test
npm run build
```

Node.js 22.18 or later. The tests run the TypeScript sources as they are, against a stub provider. `npm run build` compiles the library to `dist/`. The unit suite in a container is `docker build --target test .`. That target is not the default image, so `docker build .` still produces the demo.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library trusts every certificate in it, in addition to Node's own store.

`scripts/configure-iya-sts.ts`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`; the client secret stays out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `node scripts/trust-chain.mjs --config demo/oidc.json` refreshes it by hand. Compose still mounts `demo/generated` (for the client secret), which hides the image's copy behind the host's file.

## Live sign-in

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts and checks two Shared Signals events. It uses the host's Python and Docker. It does not import this library, and it does not run Node on the host. It starts iya-sts, copies this checkout to a scratch build context, builds the demo image, and runs the install script `node scripts/configure-iya-sts.ts` inside it (`docker run --network host`), which writes the `tlsCa` chain. Then it builds the demo image again, checks the image carries the chain and nothing else from `demo/generated`, and starts the demo with no CA mount and `TLS_CA_REFRESH=0`. `GET /live-status` returns `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It carries no tokens. Every accepted event is recorded before the receiver polls. A `session-revoked` event leaves `signedIn` false. `IYA_STS_URL` uses a running iya-sts; `IYA_STS_IMAGE` starts one from that image; otherwise iya-sts main is cloned and built. `LIVE_STS_PORT` and `LIVE_DEMO_PORT` pick the ports (defaults 18545 and 18645).

`.github/workflows/nightly.yml` runs `docker build --target test .`, then that script, at 06:03 UTC and on demand. Do not bind port 3000, 8081, or 18481 to 18495. Push and pull-request CI stays [tests.yml](.github/workflows/tests.yml).
