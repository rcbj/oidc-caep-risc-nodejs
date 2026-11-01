---
title: oidc-caep-risc-nodejs
---

# oidc-caep-risc-nodejs

A **confidential OpenID Connect client** for **server-side** Node.js applications: the traditional web application that renders its pages on the server and keeps its session there. It covers:

- **Authorization Code with PKCE**, always S256. The browser carries a code. Tokens stay in the server.
- **Client authentication** at the token endpoint: `client_secret_basic` (the default), `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.
- **The same discovery document and the same scopes** as [oidc-caep-client](https://github.com/rcbj/oidc-caep-client): `openid profile email offline_access ssf.read ssf.manage`. That project is a browser application. This one is not.
- **ID tokens checked** against the provider's JWKS: issuer, audience, nonce, age, `at_hash` and `c_hash`, and a signature algorithm the provider actually advertises.
- **CAEP and RISC** on one Shared Signals poll stream, authenticated with the application's own client-credentials token (`ssf.manage`).

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
const who = await rp.complete(query, request);
console.log(who.subject, who.email);
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
