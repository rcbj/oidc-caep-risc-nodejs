# oidc-caep-risc-nodejs

A **confidential OpenID Connect client** for server-side Node.js applications: Authorization Code (OpenID Connect Core section 3.1) with PKCE (RFC 7636), client authentication at the token endpoint, and a CAEP and RISC receiver on one Shared Signals poll stream (RFC 8936). Written in TypeScript, usable from JavaScript (ESM, or `require()` on Node 22.12+). One runtime dependency: [`jose`](https://github.com/panva/jose). Everything else is `node:crypto`, `node:http` and `node:https`.

The client is confidential. `token_endpoint_auth_method` of `none` is refused. A public client belongs in [oidc-caep-client](https://github.com/rcbj/oidc-caep-client), which is a browser application. The discovery URL and the default scopes here are the same ones that project uses.

**Documentation:** <https://rcbj.github.io/oidc-caep-risc-nodejs/> (guide, Shared Signals, API reference)

```sh
npm install oidc-caep-risc-nodejs
```

It speaks no web framework. The calls take and return plain values, so it fits Express, Fastify, Koa or `node:http` alike. See the [server-side guide](docs/guide.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).

## Quick look

```ts
import { RelyingParty, OidcError } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');

// GET /login. Keep the transaction (state, nonce, code verifier) until the browser comes back.
const request = await rp.authorize();
// redirect the browser to request.url

// GET /callback
try {
  const who = await rp.complete(query, request, { session: mySessionId });
  // who.subject, who.email, who.claims. The tokens stay in this process, cached under mySessionId.
} catch (err) {
  if (err instanceof OidcError) console.warn(err.code, err.message);
}

// Later: a valid access token for that session, refreshed when it is about to expire.
const token = await rp.accessToken(mySessionId);   // { accessToken, tokenType: 'DPoP' or 'Bearer', expiresAt }
```

From JavaScript it is the same without the types:

```js
const { RelyingParty } = await import('oidc-caep-risc-nodejs');   // or require('oidc-caep-risc-nodejs') on Node 22.12+
```

## The configuration

Names follow oidc-caep-client where the two overlap (`metadataUrl`, `client_id`, `scopes` as one string).

```json
{
  "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
  "client_id": "app",
  "clientSecret": "env:OIDC_CLIENT_SECRET",
  "redirectUri": "https://app.example/callback",
  "postLogoutRedirectUri": "https://app.example/",
  "scopes": "openid profile email offline_access ssf.read ssf.manage",
  "tokenEndpointAuthMethod": "client_secret_basic"
}
```

| Setting | Default | |
|---|---|---|
| `metadataUrl` | one of this or `metadataFile` | The provider's `/.well-known/openid-configuration`. The issuer is the URL with that suffix removed, and the document's `issuer` must equal it. |
| `metadataFile` | — | A metadata document on disk, used instead of fetching `metadataUrl`. |
| `client_id` | required | Also accepted as `clientId`. |
| `clientSecret` | required for the secret methods | The secret, `env:NAME`, or `file:path` (relative to the configuration file). |
| `privateKey` | required for `private_key_jwt` | PEM PKCS#8, a path, `env:` or `file:`. |
| `privateKeyAlg` | `RS256` | The algorithm of the client assertion. |
| `tokenEndpointAuthMethod` | `client_secret_basic` | `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. `none` is refused. |
| `redirectUri` | required | Where the provider sends the browser. `https`, or `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). Also `redirect_uri`. A per-request `redirectUri` passed to `authorize` is held to the same rule. |
| `postLogoutRedirectUri` | — | Sent on the end-session URL when the provider has one. The same rule as `redirectUri`. |
| `scopes` | `openid profile email offline_access ssf.read ssf.manage` | A space-separated string, or an array. Must include `openid`. `signals: false` removes `ssf.read` and `ssf.manage` after the default is applied. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithms accepted. Each must also be advertised by the provider (the accepted set is the overlap; an empty overlap fails at creation). `none` is refused. An HMAC algorithm is accepted only when it is named, and the client secret is the key. |
| `idTokenSignedResponseAlg` | — | Pin one `alg`. When set it replaces `idTokenSigningAlgs`, and it must be advertised. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt`, and when the token response carries an access token the ID token must carry a matching `at_hash`. `false` checks each only when it is present, for a provider that omits them. |
| `acrValues` | — | `acr_values` for every authorization request (a space-separated string or an array). The ID token from the code exchange must carry `acr`, and it must be one of them. |
| `par` | `auto` | `auto` uses pushed authorization when the provider advertises it, `always` requires it, `never` puts the parameters on the authorization URL. When the provider sets `require_pushed_authorization_requests`, `auto` always pushes and `never` fails at creation. |
| `dpop` | `auto` | DPoP (RFC 9449). `auto` uses it when the provider's `dpop_signing_alg_values_supported` includes `ES256`, `always` fails at creation when it does not, `never` sends no proofs. |
| `dpopKey` | — | The DPoP private key: a P-256 PEM, a path, `env:` or `file:`. Without it, an ES256 key is generated when the relying party is created and held in memory only. Name one when several processes share sign-ins. |
| `clockToleranceSec` | `30` | How far the two clocks may disagree, for the ID token's `exp`, `iat` and `auth_time`. An `iat` further than this in the future is refused. |
| `maxIdTokenAgeSec` | `600` | Refuse an ID token whose `iat` is older than this. |
| `allowInsecure` | `false` | Allow an `http` issuer and endpoints. It does not relax the redirect-URI rule. |
| `tlsCa` | — | CA trust chain for the provider's TLS listener. PEM, `file:path`, `env:NAME`, or a path, trusted in addition to node's own store. A missing file is ignored. |
| `signals` | on | `false` turns CAEP and RISC off. No `ssf` block is resolved, the transmitter is not contacted, and `ssf.read` and `ssf.manage` are not requested. Anything other than `true` or `false` is an error. Omitted is the same as `true`. |
| `ssf.transmitter` | — | The Shared Signals transmitter, used when signals are on. Its configuration is read from `/.well-known/ssf-configuration`. |
| `ssf.pollIntervalMs` | `5000` | How long the receiver waits between empty polls. |

`RelyingParty.create(config)` takes the same members after `resolveConfig` has read the files. A configuration built by hand gets the same defaults and the same checks: the members with a default may be left out, and the redirect URIs are held to the same rule. `RelyingParty.create(config, { tokenStore })` and `RelyingParty.fromFile(path, { tokenStore })` take the session cache's store (see below).

## What a sign-in does

`authorize` always sends `response_type=code`, `state`, `nonce`, and PKCE S256, `acr_values` when the setting or the request names any, and `dpop_jkt` when DPoP is in use. With `par` of `auto` or `always`, and a provider that has a pushed authorization endpoint, those parameters are posted there (with client authentication and a DPoP proof) and the browser is sent only `client_id` and `request_uri`. The requested `acr_values` are kept in the transaction.

`prompt=login` asks the provider to authenticate again, which is how a second account is added in one browser. `expectedSub` makes `complete` refuse a callback that comes back as someone else.

`complete` refuses an access token, ID token, or refresh token on the redirect. It checks `state`, checks `iss` (and requires it when the provider advertises `authorization_response_iss_parameter_supported`), and accepts a code once. The token request authenticates the client, sends the code verifier, and carries a DPoP proof when DPoP is in use. The response must carry an ID token, and its `token_type` must be `DPoP` when a proof was sent and `Bearer` when none was (case-insensitive).

The ID token is verified with `jose` against the provider's JWKS (fetched with this process's TLS settings, not by `jose` itself):

- `alg` is the pinned one, or one of `idTokenSigningAlgs` (default `RS256`) that the provider advertises. `none` is refused. HMAC is refused unless it was named.
- `typ` is `JWT` or `application/jwt`, in any case; `requireIdTokenTypAndAtHash: false` also lets it be absent. `at+jwt`, `secevent+jwt`, and a header with `crit` are refused.
- `iss`, `aud` (and `azp` when the audience has more than this client), `nonce`, `exp`, `iat` within `maxIdTokenAgeSec` and not more than `clockToleranceSec` in the future, and `auth_time` when `max_age` was sent.
- `acr`, when `acr_values` was requested: present, and one of the requested values. A refresh does not check `acr` again.
- `at_hash` against the access token: required whenever the token response carries one, unless `requireIdTokenTypAndAtHash` is `false` (then checked when present). `c_hash`, when present, against the code.
- A refresh that returns a new ID token must name the same `sub`.

`clientCredentials(scope)` takes an access token for the application itself, with a DPoP proof when DPoP is in use. The demo's receiver uses it with `ssf.manage`, through `signalsRequest`.

## DPoP

With `dpop` of `auto` (the default) and a provider that advertises `ES256` in `dpop_signing_alg_values_supported`, the relying party generates a P-256 key when it is created (or reads `dpopKey`) and signs a proof (`typ: dpop+jwt`, the public `jwk` in the header, `jti`, `htm`, `htu` without query or fragment, `iat`) for every request to the PAR endpoint and the token endpoint (code, refresh and client-credentials grants), and for every resource request made with a DPoP-bound token: UserInfo, `fetchResource`, and every call `signalsRequest` sends to the Shared Signals transmitter. A resource proof also carries `ath`. `usesDpop` and `dpopThumbprint` say whether it is in use and with which key.

A 400 `use_dpop_nonce` from the authorization server, or a 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` from a resource server, is retried once with the nonce the response gave. The latest `DPoP-Nonce` from each server origin is kept and sent on the next proof to it.

`fetchResource(url, { method, headers, body }, { accessToken, tokenType })` calls a resource server with a token: `Authorization: DPoP` and a proof for a DPoP token, `Authorization: Bearer` for a Bearer one. `dpopProof(method, url, accessToken?)` signs a proof for a call the application makes itself.

## The session cache

`complete(query, transaction, { session })` caches the sign-in's tokens under `session`, an id the application chooses (its own session id). Without one, the relying party makes one and returns it as `login.session`. `accessToken(session)` returns a valid access token for that session: the cached one while it has more than 30 seconds left, otherwise a new one from the refresh token (with a DPoP proof when DPoP is in use), which replaces the cached tokens. A failed refresh, or an expired token with no refresh token, removes the session and is refused. `removeSession(session)` clears it at sign-out; a `SignalsReceiver` given `relyingParty` clears it when an event (such as CAEP `session-revoked`) ends the session, and on `untrack`. `sessionTokens(session)` returns what is cached.

The default store is this process's memory (`MemoryTokenStore`). A `TokenStore` (`get`, `set`, `delete`, each may return a promise) can replace it, for a store shared by several processes. A shared store should also share the DPoP key (`dpopKey`), since cached DPoP tokens are bound to it.

`endSessionUrl` builds the RP-initiated logout URL when the provider advertises `end_session_endpoint`. The demo signs out of the application locally and leaves that URL to the caller.

## Shared Signals

The default is on. `signals: false` turns CAEP and RISC off, drops `ssf.read` and `ssf.manage`, and does not contact a transmitter. Sign-in is unchanged. With a transmitter, and with signals left on, `SignalsReceiver` keeps one poll stream for the whole application. Authentication is `request: rp.signalsRequest('ssf.manage')` (a client-credentials token, DPoP-bound with a proof on every call when DPoP is in use), whatever `headers` returns, or a TLS client certificate. Every SET is verified before it is acted on. A caller who constructs `SignalsReceiver` has opted in. See [Handling CAEP and RISC events](docs/signals.md).

## Errors

Every failure is an `OidcError`. `code` is `config`, `discovery`, `protocol`, `validation`, `signature`, or `ssf`. A provider error also sets `oauthError` to the `error` code it sent.

```sh
npx oidc-caep-risc-nodejs check --config oidc.json
```

prints the client id, the authentication method, the redirect URI, the scopes, the PAR and DPoP modes, the accepted ID token algorithms, the `acr_values`, and whether a secret is present. It does not print the secret, and it does not contact the provider.
