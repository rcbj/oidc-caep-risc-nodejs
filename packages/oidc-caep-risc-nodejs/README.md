# oidc-caep-risc-nodejs

A **confidential OpenID Connect client** for server-side Node.js applications: Authorization Code (OpenID Connect Core section 3.1) with PKCE (RFC 7636), client authentication at the token endpoint, and a CAEP and RISC receiver on one Shared Signals poll stream (RFC 8936). Written in TypeScript, usable from JavaScript (ESM, or `require()` on Node 22.12+). One runtime dependency: [`jose`](https://github.com/panva/jose). Everything else is `node:crypto`, `node:http` and `node:https`.

The client is confidential. `token_endpoint_auth_method` of `none` is refused. A public client belongs in [oidc-caep-client](https://github.com/rcbj/oidc-caep-client), which is a browser application. The discovery URL and the default scopes here are the same ones that project uses.

**Documentation:** <https://rcbj.github.io/oidc-caep-risc-nodejs/> (guide, Shared Signals, API reference)

```sh
npm install oidc-caep-risc-nodejs
```

It speaks no web framework. The calls take and return plain values, so it fits Express, Fastify, Koa or `node:http` alike. See the [server-side guide](docs/guide.md).

## License

Business Source License 1.1. See [LICENSE](LICENSE). Production use requires a commercial license from Iya CyberSecurity Solutions, LLC, granted only as part of a paid support subscription.

## Quick look

```ts
import { RelyingParty, OidcError } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');

// GET /login. Keep the transaction (state, nonce, code verifier) until the browser comes back.
const request = await rp.authorize();
// redirect the browser to request.url

// GET /callback
try {
  const who = await rp.complete(query, request);
  // who.subject, who.email, who.claims. The tokens stay in this process.
} catch (err) {
  if (err instanceof OidcError) console.warn(err.code, err.message);
}
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
| `redirectUri` | required | Where the provider sends the browser. `https`, or `http` on loopback. Also `redirect_uri`. |
| `postLogoutRedirectUri` | — | Sent on the end-session URL when the provider has one. |
| `scopes` | `openid profile email offline_access ssf.read ssf.manage` | A space-separated string, or an array. Must include `openid`. |
| `idTokenSignedResponseAlg` | every asymmetric algorithm the provider advertises | Pin one `alg`. HMAC is accepted only when it is pinned, and the client secret is the key. |
| `par` | `auto` | `auto` uses pushed authorization when the provider advertises it, `always` requires it, `never` puts the parameters on the authorization URL. |
| `clockToleranceSec` | `30` | How far the two clocks may disagree, for the ID token. |
| `maxIdTokenAgeSec` | `600` | Refuse an ID token whose `iat` is older than this. |
| `allowInsecure` | `false` | Allow an `http` issuer. Loopback `http` redirect URIs are allowed either way. |
| `tlsCa` | — | CA trust chain for the provider's TLS listener. PEM, `file:path`, `env:NAME`, or a path, trusted in addition to node's own store. A missing file is ignored. |
| `ssf.transmitter` | — | The Shared Signals transmitter. Its configuration is read from `/.well-known/ssf-configuration`. |
| `ssf.pollIntervalMs` | `5000` | How long the receiver waits between empty polls. |

`RelyingParty.create(config)` takes the same members after `resolveConfig` has read the files.

## What a sign-in does

`authorize` always sends `response_type=code`, `state`, `nonce`, and PKCE S256. With `par` of `auto` or `always`, and a provider that has a pushed authorization endpoint, those parameters are posted there (with client authentication) and the browser is sent only `client_id` and `request_uri`.

`prompt=login` asks the provider to authenticate again, which is how a second account is added in one browser. `expectedSub` makes `complete` refuse a callback that comes back as someone else.

`complete` refuses an access token, ID token, or refresh token on the redirect. It checks `state`, checks `iss` (and requires it when the provider advertises `authorization_response_iss_parameter_supported`), and accepts a code once. The token request authenticates the client and sends the code verifier. The response must be a Bearer token with an ID token.

The ID token is verified with `jose` against the provider's JWKS (fetched with this process's TLS settings, not by `jose` itself):

- `alg` is the pinned one, or one of the asymmetric algorithms the provider advertises. `none` is refused. HMAC is refused unless it was pinned.
- `typ` is absent or `JWT`. `at+jwt`, `secevent+jwt`, and a header with `crit` are refused.
- `iss`, `aud` (and `azp` when the audience has more than this client), `nonce`, `exp`, `iat` within `maxIdTokenAgeSec`, and `auth_time` when `max_age` was sent.
- `at_hash` and `c_hash`, when present, against the access token and the code.
- A refresh that returns a new ID token must name the same `sub`.

`clientCredentials(scope)` takes an access token for the application itself. The demo's receiver uses it with `ssf.manage`. A `token_type` of `DPoP` is refused: this client sends Bearer tokens.

`endSessionUrl` builds the RP-initiated logout URL when the provider advertises `end_session_endpoint`. The demo signs out of the application locally and leaves that URL to the caller.

## Shared Signals

With a transmitter, `SignalsReceiver` keeps one poll stream for the whole application. Authentication is whatever `headers` returns (a Bearer token from `clientCredentials`) or a TLS client certificate. Every SET is verified before it is acted on. See [Handling CAEP and RISC events](docs/signals.md).

## Errors

Every failure is an `OidcError`. `code` is `config`, `discovery`, `protocol`, `validation`, `signature`, or `ssf`. A provider error also sets `oauthError` to the `error` code it sent.

```sh
npx oidc-caep-risc-nodejs check --config oidc.json
```

prints the client id, the authentication method, the redirect URI, the scopes, and whether a secret is present. It does not print the secret, and it does not contact the provider.
