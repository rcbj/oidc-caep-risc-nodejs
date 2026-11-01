# oidc-caep-risc-nodejs

A confidential OpenID Connect relying party for a traditional Node.js application, and a CAEP and RISC receiver on one Shared Signals poll stream. It is TypeScript, usable from JavaScript, and depends on `jose` only. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

The browser library is [oidc-caep-client](https://github.com/rcbj/oidc-caep-client). It is a public client. This one is not. The discovery URL and the default scopes match.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied.

Documentation: <https://rcbj.github.io/oidc-caep-risc-nodejs/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 22.18 or later. The package engines field says `>=22.18.0`. Continuous integration runs the suite on 22.18.0 and 24.22.1.

## Layout

| Path | What it is |
|---|---|
| `packages/oidc-caep-risc-nodejs` | The library published to npm as `oidc-caep-risc-nodejs`. Source is `src/` (`relying-party.ts`, `client-auth.ts`, `id-token.ts`, `pkce.ts`, `discovery.ts`, `ssf/`). Tests are `test/`. `npm run build` writes `dist/`. |
| `demo` | The server-rendered demo. `demo/server.ts` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure-iya-sts.ts` registers the confidential client on iya-sts. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc. It is outside the npm workspace. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

The root `package.json` is a private workspace. Committed manifests stay at `M.N.0` from the root `VERSION` file.

## Usage

```sh
npm install oidc-caep-risc-nodejs
```

```ts
import { RelyingParty, OidcError } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');
const request = await rp.authorize();
// redirect the browser to request.url
const who = await rp.complete(query, request);
```

Keep the transaction (`state`, nonce, code verifier) until the browser returns. Tokens stay in this process. The package README and `packages/oidc-caep-risc-nodejs/docs/guide.md` are the reference.

## Tests

```sh
npm ci
npm test
npm run build
npm run version:check
```

`npm test` runs `node:test` on the TypeScript sources in `packages/oidc-caep-risc-nodejs/test` and on `scripts/*.test.ts`. The library tests use a stub provider and a stub transmitter. `version:check` fails unless every manifest is `M.N.0`.

`.github/workflows/tests.yml` also builds the demo image and checks what it serves. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… OIDC_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `oidc-demo-user`.

A loopback redirect follows `PORT` in the running server and in `scripts/configure-iya-sts.ts`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
