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

Node.js 22.18 or later. The tests run the TypeScript sources as they are, against a stub provider. `npm run build` compiles the library to `dist/`.
