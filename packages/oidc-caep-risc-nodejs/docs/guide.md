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

The request is Authorization Code with PKCE S256. `state` and `nonce` are new every time. When the provider advertises a pushed authorization endpoint, the parameters are posted there and the browser is sent only `client_id` and `request_uri`.

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
const who = await rp.complete(new URL(req.url, 'https://app.example').searchParams, transaction);
```

`complete` refuses tokens on the query string, checks `state` and `iss`, accepts the code once, authenticates at the token endpoint, and verifies the ID token (issuer, audience, nonce, time, `at_hash` and `c_hash` when they are present, signature against the provider's JWKS). Then redirect (303) to the signed-in page so the code leaves the address bar.

Store a session of your own. Eight hours is what the demo uses. The access token's `expires_in` is not that session: call `refresh` when the application itself needs a new access token, and pass the previous login so a new ID token is checked against the same subject.

```ts
const next = await rp.refresh(who.refreshToken, { previous: who });
```

## 4. Several people in one browser

The demo keeps an account set in one cookie and gives each person their own URL, `/u/<account>/`. Two tabs can show two people. Signing the same person in again replaces that account and keeps its URL. An event that ends one account does not change what another tab shows.

On iya-sts, `authn.multipleAccounts` has to be on, or the provider ends the first person's session when the second signs in. The setup script turns it on.

## 5. Signing out

Signing out of the application is local: forget the session. The library also builds the provider's end-session URL when the metadata has `end_session_endpoint`:

```ts
const url = rp.endSessionUrl({ idToken: who.idToken, postLogoutRedirectUri: 'https://app.example/' });
```

The demo does not send the browser there. It signs the account out of this application, and leaves the others in the same browser signed in. "Sign out of all accounts" clears the set.

## 6. What the page shows

Show the subject, the issuer, the email, the name. Do not render the access token, the refresh token, or the ID token. The demo's identity tab is that list and nothing else.
