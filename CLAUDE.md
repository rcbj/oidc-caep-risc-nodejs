# oidc-caep-risc-nodejs

A confidential OpenID Connect relying party for a traditional Node.js application, and a CAEP and RISC receiver on one Shared Signals poll stream. It is TypeScript, usable from JavaScript, and depends on `jose` only. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

The client profile (issue #31, the same settings and defaults in the six sibling libraries in Python, Java, Rust, Go, C# and C): `par` `auto` (always pushes when the provider sets `require_pushed_authorization_requests`, and `never` then fails at creation); `dpop` `auto`/`always`/`never` (ES256 key made at creation, or `dpopKey`; proofs on PAR, token, UserInfo and every SSF transmitter call; `dpop_jkt`; one `use_dpop_nonce` retry; `token_type` must be `DPoP` with a proof and `Bearer` without); `acrValues` (the ID token `acr` must be one of the requested values; not rechecked on refresh); `idTokenSigningAlgs` default `["RS256"]` (overlap with the advertised list, `none` never, HMAC only when named; `idTokenSignedResponseAlg` pins one); `requireIdTokenTypAndAtHash` default true; `clockToleranceSec` 30 and `maxIdTokenAgeSec` 600. `finishConfig()` (src/config.ts) applies the defaults and the redirect-URI rule (https, or http on `localhost`, `127.0.0.1`, `[::1]`; `allowInsecure` does not relax it) to both `resolveConfig` and `RelyingParty.create`. `complete(..., { session })` caches tokens in a `TokenStore` (default `MemoryTokenStore`); `accessToken(session)` refreshes with 30 s or less left and removes the session on a failed refresh. Keep these names and defaults in step with the siblings.

The browser library is [oidc-caep-client](https://github.com/rcbj/oidc-caep-client). It is a public client. This one is not. The discovery URL and the default scopes match.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied.

Documentation: <https://rcbj.github.io/oidc-caep-risc-nodejs/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 22.18 or later. The package engines field says `>=22.18.0`. Continuous integration runs the suite on 22.18.0 and 24.22.1.

## Layout

| Path | What it is |
|---|---|
| `packages/oidc-caep-risc-nodejs` | The library published to npm as `oidc-caep-risc-nodejs`. Source is `src/` (`relying-party.ts`, `config.ts`, `client-auth.ts`, `id-token.ts`, `dpop.ts`, `token-store.ts`, `pkce.ts`, `discovery.ts`, `ssf/`). Tests are `test/`: `rp.test.ts`, `profile.test.ts` (issue #31, point by point), `ssf.test.ts`, against `test/stub-provider.ts` (a stub provider with PAR, DPoP and nonces) and stub transmitters. `npm run build` writes `dist/`. |
| `demo` | The server-rendered demo. `demo/server.ts` and `demo/public/`. Config is `demo/oidc.json`. An error is logged with its stack and the page shows a fixed sentence; a refused sign-in shows the label of its `OidcError` code. Never render an error's message. |
| `scripts` | `configure-iya-sts.ts`, the install script, registers the confidential client on iya-sts (with `oauthIdTokenSignedResponseAlg` `RS256`) and writes the listener CA trust chain to the file `tlsCa` names. `trust-chain.mjs` holds `saveTrustChain()` and refreshes that file. `trust-chain.test.ts`: the chain is written whole to `tlsCa`'s path, and the library trusts a provider through it. `demo-errors.test.ts` starts `demo/server.ts` and holds that no page and no `/live-status` answer carries an exception's text or a provider `error_description`. `live_iya_sts.py` is the host Python live sign-in. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
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

Keep the transaction (`state`, nonce, code verifier, requested `acrValues`) until the browser returns. Tokens stay in this process, in the session cache: pass the application's session id to `complete(query, request, { session })` and call `rp.accessToken(session)` for a valid access token. The demo does that, sends its SSF calls through `rp.signalsRequest('ssf.manage')`, and gives the receiver `relyingParty: rp`. The package README and `packages/oidc-caep-risc-nodejs/docs/guide.md` are the reference.

## Tests

```sh
npm ci
npm test
npm run build
npm run version:check
```

`npm test` builds the library first (`pretest`: `scripts/demo-errors.test.ts` runs the demo, which imports the built package), then runs `node:test` on the TypeScript sources in `packages/oidc-caep-risc-nodejs/test` and on `scripts/*.test.ts`. The library tests use a stub provider and a stub transmitter. `version:check` fails unless every manifest is `M.N.0`.

The unit suite is `docker build --target test .`. That stage runs `npm test` in the image. It is not the default target, so `docker build .` and `docker compose build` still produce the demo.

`.github/workflows/tests.yml` also builds the demo image and checks what it serves. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts in memory mode, with persistence and clustering off and no request workers, unless `IYA_STS_URL` is already set. It uses the host's Python and Docker. It does not import this library and does not run Node on the host. It copies the checkout to a scratch build context, builds the demo image, runs `scripts/configure-iya-sts.ts` inside it (`docker run --network host`), which writes the `tlsCa` chain into the context, then builds the image again, checks it carries that chain (and nothing else from `demo/generated`), and starts the demo with only the client secret mounted and `TLS_CA_REFRESH=0`. It never rewrites `tlsCa` or fetches the CA for the demo. The demo container is `oidc-caep-risc-nodejs-live-demo`. `IYA_STS_URL` uses a running iya-sts and does not stop it. `IYA_STS_IMAGE` starts a fresh `iya-sts-live-oidc-caep-risc-nodejs` container from that image. With neither, it clones and builds iya-sts main, which is what the nightly run does. `LIVE_STS_PORT` (default 18545) and `LIVE_DEMO_PORT` (default 18645) pick the ports. A second run against an iya-sts that already has the client fails, so use a fresh one. Do not bind port 3000, 8081, or 18481 to 18495.

`.github/workflows/nightly.yml` runs `docker build --target test .`, then the live script, on the cron `3 6 * * *` and on `workflow_dispatch`. `tests.yml` stays the push and pull-request CI.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library trusts every certificate in it, in addition to Node's own store.

`scripts/configure-iya-sts.ts`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`; the client secret stays out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. The refresh verifies the provider against the chain the file already holds; only when that chain cannot verify it (no file yet, or a new CA) does it take the provider's chain on first use, still checking that it names the host and is signed link by link, and it prints the root's SHA-256 to compare with iya-sts's PKI page. `TLS_CA_REFRESH=0` turns the refresh off. `node scripts/trust-chain.mjs --config demo/oidc.json` refreshes it by hand. Compose still mounts `demo/generated` (for the client secret), which hides the image's copy behind the host's file.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… OIDC_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `oidc-demo-user`. Unless `OIDC_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/oidc-demo-user.password` (created mode 0600) and prints only that path, never the password.

`GET /live-status` returns JSON: `signedIn`, `subject`, `receiver`, and `events` (`type` and `jti` only). No access token, refresh token, or ID token. The receiver records every accepted event before it starts polling. `session-revoked` ends the matching local session, so `signedIn` is false.

A loopback redirect follows `PORT` in the running server and in `scripts/configure-iya-sts.ts`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory (not its tests), `VERSION`, or `package-lock.json`. A change that is only this file, the demo, the docs, the tests, `scripts/version.mjs`, or that workflow does not publish. Every publish, `latest` and `next`, gets a tag and a GitHub Release; `next` is marked a pre-release. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
