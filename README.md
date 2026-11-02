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

Open <http://localhost:3000> and sign in as `oidc-demo-user`. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## Develop

```sh
npm install
npm test
npm run build
```

Node.js 22.18 or later. The tests run the TypeScript sources as they are, against a stub provider. `npm run build` compiles the library to `dist/`. The unit suite in a container is `docker build --target test .`. That target is not the default image, so `docker build .` still produces the demo.

## Live sign-in

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts and checks two Shared Signals events. It uses the host's Python and Docker. It does not import this library, and it does not run Node on the host. The demo image runs `node scripts/configure-iya-sts.ts` through its entrypoint (`docker run --network host`), then the demo. `GET /live-status` returns `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It carries no tokens. Every accepted event is recorded before the receiver polls. A `session-revoked` event leaves `signedIn` false. `IYA_STS_URL` uses a running iya-sts; `IYA_STS_IMAGE` starts one from that image; otherwise iya-sts main is cloned and built. `LIVE_STS_PORT` and `LIVE_DEMO_PORT` pick the ports (defaults 18501 and 18601).

`.github/workflows/nightly.yml` runs `docker build --target test .`, then that script, at 06:03 UTC and on demand. Do not bind port 3000 or 8081. Push and pull-request CI stays [tests.yml](.github/workflows/tests.yml).
