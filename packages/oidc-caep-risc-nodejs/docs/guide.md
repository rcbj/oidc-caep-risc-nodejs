# Adding OpenID Connect sign-in to a server-side web application

This walks through a traditional, server-rendered application: the configuration, the login route, the callback, and the session. The [demo](../../../demo/server.ts) is all of it in one file with `node:http`.

The client is confidential. The browser only ever carries an authorization code. Tokens stay in the server process, and the pages do not render them.

## 1. The configuration

```json
{
  "metadataUrl": "https://idp.example/.well-known/openid-configuration",
  "client_id": "app",
  "clientSecret": "env:OIDC_CLIENT_SECRET",
  "redirectUri": "https://app.example/callback",
  "postLogoutRedirectUri": "https://app.example/",
  "scopes": "openid profile email offline_access ssf.read ssf.manage",
  "tokenEndpointAuthMethod": "client_secret_basic",
  "tlsCa": "keys/idp-ca.pem"
}
```

`scopes` is the same string [oidc-caep-client](https://github.com/rcbj/oidc-caep-client) registers. `metadataUrl` is that project's name for the discovery document. `client_secret_basic` is what iya-sts writes when a client is created with a secret. `tlsCa` is the CA trust chain for the provider's TLS listener: a PEM bundle, `file:path`, `env:NAME`, or a path. iya-sts publishes that bundle at `GET /tls/server-certificate`. A missing file is ignored, so the process can still serve a page before the file exists.

CAEP and RISC are on by default. `signals: false` turns them off for a provider that does not implement Shared Signals. The client then does not resolve an `ssf` block, does not contact a transmitter, and does not request `ssf.read` or `ssf.manage`. `openid` is still required. Sign-in is otherwise the same.

The defaults hold the client to a strict profile, and each can be named in the file:

| Setting | Default | |
|---|---|---|
| `par` | `auto` | Pushed authorization when the provider has an endpoint for it; always when the provider sets `require_pushed_authorization_requests` (then `never` fails at creation). |
| `dpop` | `auto` | DPoP-bound tokens when the provider advertises `ES256` in `dpop_signing_alg_values_supported`. `always` fails at creation when it does not; `never` sends no proofs. |
| `dpopKey` | a key made at creation | A P-256 PEM (a path, `file:` or `env:`), for several processes that share sign-ins. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithms accepted, each also advertised by the provider. `none` never; HMAC only when named. `idTokenSignedResponseAlg` pins one. |
| `requireIdTokenTypAndAtHash` | `true` | `typ` (`JWT` or `application/jwt`) and `at_hash` are required. `false` checks them only when present. |
| `acrValues` | — | `acr_values` on every request; the ID token's `acr` must be one of them. |
| `clockToleranceSec` | `30` | Clock skew allowed; an `iat` further in the future is refused. |
| `maxIdTokenAgeSec` | `600` | The oldest ID token `iat` accepted. |

The redirect URIs must be `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`. The same defaults and the same rule apply to a configuration object passed straight to `RelyingParty.create`, and to a redirect URI passed to `authorize`.

Keep the secret out of the image and out of version control. `env:OIDC_CLIENT_SECRET` reads it from the environment. `file:keys/client-secret` reads it from a file next to the configuration.

For iya-sts, [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) registers the application, writes the secret, and saves the listener CA trust chain into the file `tlsCa` names. The demo container refreshes that file when it starts.

## 2. The login route

```ts
import { RelyingParty } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');

// GET /login
const request = await rp.authorize();
// Store request (state, nonce, codeVerifier, redirectUri) with this browser.
// Redirect the browser to request.url.
```

The request is Authorization Code with PKCE S256. `state` and `nonce` are new every time. When the provider advertises a pushed authorization endpoint, the parameters are posted there and the browser is sent only `client_id` and `request_uri`. With DPoP in use, the request carries `dpop_jkt`, the thumbprint of this process's DPoP key, and the push carries a proof.

To require an authentication context, name it: `acrValues` in the configuration, or per request:

```ts
const request = await rp.authorize({ acrValues: 'urn:example:acr:mfa' });
```

The requested values are kept in the transaction, and the callback refuses an ID token whose `acr` is missing or not one of them.

Adding another person in the same browser, or signing one person in again, asks the provider not to reuse single sign-on silently:

```ts
const request = await rp.authorize({
  prompt: 'login',
  loginHint: person.preferredUsername || person.email,
  expectedSub: person.subject,
});
```

`expectedSub` makes the callback fail if the provider authenticates someone else.

The transaction has to survive until the callback. The demo seals it in an `HttpOnly` cookie, `oidc_txn`, scoped to `/callback`, `SameSite=Lax`. A top-level redirect back from the provider sends a Lax cookie. Sign the cookie. Do not put the code verifier anywhere the page's script can read.

## 3. The callback

```ts
// GET /callback
const sessionId = newSessionId();   // the application's own session id
const who = await rp.complete(new URL(req.url, 'https://app.example').searchParams, transaction, { session: sessionId });
```

`complete` refuses tokens on the query string, checks `state` and `iss`, accepts the code once, authenticates at the token endpoint (with a DPoP proof when DPoP is in use), and verifies the ID token (signature against the provider's JWKS with an allowed algorithm, `typ`, issuer, audience, nonce, time, `acr` when it was requested, `at_hash`, and `c_hash` when it is present). Then redirect (303) to the signed-in page so the code leaves the address bar.

Store a session of your own. Eight hours is what the demo uses. The relying party caches the sign-in's tokens under the session id you passed (or one it makes and returns as `who.session`). When the application needs to call an API, ask for a valid access token:

```ts
const token = await rp.accessToken(sessionId);
const info = await rp.userinfo(token.accessToken, who.subject, { tokenType: token.tokenType });
const answer = await rp.fetchResource('https://api.example/things', { method: 'GET' }, token);
```

`accessToken` returns the cached token while it has more than 30 seconds left, and otherwise refreshes it (with a DPoP proof when DPoP is in use) and caches the result. A failed refresh removes the session and throws: send the person to sign in again. `fetchResource` presents a DPoP token with a proof (`ath`, and a retry when the server asks for a nonce) and a Bearer token as it is.

The cache is this process's memory unless you pass a store. An application that runs several processes passes one shared store to each, and names `dpopKey` so they present the same DPoP key:

```ts
const rp = await RelyingParty.fromFile('oidc.json', { tokenStore: myRedisTokenStore });
```

`refresh` is still there for an application that keeps the tokens itself; pass the previous login so a new ID token is checked against the same subject.

## 4. Several people in one browser

The demo keeps an account set in one cookie and gives each person their own URL, `/u/<account>/`. Two tabs can show two people. Signing the same person in again replaces that account and keeps its URL. An event that ends one account does not change what another tab shows.

On iya-sts, `authn.multipleAccounts` has to be on, or the provider ends the first person's session when the second signs in. The setup script turns it on.

## 5. Signing out

Signing out of the application is local: forget the session, and call `rp.removeSession(sessionId)` so its cached tokens go too. A `SignalsReceiver` given `relyingParty: rp` does that itself when a CAEP or RISC event ends the session. The library also builds the provider's end-session URL when the metadata has `end_session_endpoint`:

```ts
const url = rp.endSessionUrl({ idToken: who.idToken, postLogoutRedirectUri: 'https://app.example/' });
```

The demo does not send the browser there. It signs the account out of this application, and leaves the others in the same browser signed in. "Sign out of all accounts" clears the set.

## 6. What the page shows

Show the subject, the issuer, the email, the name. Do not render the access token, the refresh token, or the ID token. The demo's identity tab is that list and nothing else.
