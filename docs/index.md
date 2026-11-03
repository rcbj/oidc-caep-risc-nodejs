---
title: oidc-caep-risc-nodejs
---

# oidc-caep-risc-nodejs

A **confidential OpenID Connect client** for **server-side** Node.js applications: the traditional web application that renders its pages on the server and keeps its session there. It covers:

- **Authorization Code with PKCE**, always S256. The browser carries a code. Tokens stay in the server.
- **Client authentication** at the token endpoint: `client_secret_basic` (the default), `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.
- **The same discovery document and the same default scopes** as [oidc-caep-client](https://github.com/rcbj/oidc-caep-client): `openid profile email offline_access ssf.read ssf.manage`. That project is a browser application. This one is not. `signals: false` removes `ssf.read` and `ssf.manage` from the authorization request.
- **ID tokens checked** against the provider's JWKS: RS256 by default (`idTokenSigningAlgs` widens it, and every allowed algorithm must be advertised; `none` never), `typ` and `at_hash` required (`requireIdTokenTypAndAtHash`), issuer, audience, nonce, age, `iat` not in the future, `c_hash`, and `acr` when `acr_values` was requested.
- **DPoP** (RFC 9449, `dpop: auto` by default): an ES256 key per relying party, a proof on the PAR and token requests, on UserInfo and on every call to the Shared Signals transmitter, `dpop_jkt` on the authorization request, and the `DPoP-Nonce` retry.
- **Pushed authorization** (`par: auto`), always used when the provider requires it.
- **A per-session token cache**: `accessToken(session)` returns a valid access token, refreshing it when it has 30 seconds or less left. The store can be replaced by a shared one.
- **CAEP and RISC** on one Shared Signals poll stream, authenticated with the application's own client-credentials token (`ssf.manage`). The default is on. `signals: false` turns CAEP and RISC off, drops those two scopes, and does not contact a transmitter.

It is TypeScript and works from JavaScript, needs no web framework, and depends on [`jose`](https://github.com/panva/jose) only. It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/).

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.

## Install

```sh
npm install oidc-caep-risc-nodejs
```

## Where to read

- **[Server-side guide](guide.md):** the configuration, the login route, the callback, and the session.
- **[Handling CAEP and RISC events](signals.md):** what the receiver ends, and how it authenticates.
- **[Configuration and API reference](reference.md):** every setting, what is checked, and the API.
- **[TypeScript API](api/)** (TypeDoc), generated from the source.
- **[Setting up iya-sts](configure.md):** registering the confidential client.
- **[Running the demo](demo.md):** a complete application in one container.
- **[Development and releases](development.md):** tests, CI, branches and versions.

## Quick look

```ts
import { RelyingParty } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');

// /login
const request = await rp.authorize();          // keep state, nonce and codeVerifier
// redirect the browser to request.url

// /callback
const who = await rp.complete(query, request, { session: mySessionId });
console.log(who.subject, who.email);

// any later request in that session
const token = await rp.accessToken(mySessionId);   // refreshed when it is about to expire
```

The configuration is the same shape oidc-caep-client uses, plus the secret:

```json
{
  "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
  "client_id": "app",
  "clientSecret": "env:OIDC_CLIENT_SECRET",
  "redirectUri": "http://localhost:3000/callback",
  "scopes": "openid profile email offline_access ssf.read ssf.manage",
  "tokenEndpointAuthMethod": "client_secret_basic"
}
```
