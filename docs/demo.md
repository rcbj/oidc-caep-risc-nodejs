---
title: Running the demo
---

# Running the demo

The demo is a traditional web application. The server renders the pages. The browser holds a session cookie, not tokens. It is the same shape as the [saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs) demo: several accounts in one browser, an identity tab, a CAEP and RISC tab, a live event stream, verify, clear, sign-out of one account, and sign-out of all of them.

## With iya-sts

iya-sts listens on `https://localhost:8081`. From this repository:

```sh
npm install
ADMIN_API_CLIENT_SECRET=… OIDC_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `oidc-demo-user`.

`configure-iya-sts` writes `demo/generated/client-secret` and `demo/generated/idp-ca.pem`. That second file is the listener CA trust chain, and it is what `tlsCa` in `demo/oidc.json` names. Compose mounts the directory into the container. The files are not in the image. When the container starts, it fetches the chain again and updates that file, so a rebuilt listener certificate is picked up without a second setup run.

The container uses the host's network, so `https://localhost:8081` is the same address inside the container as in the browser. On Docker Desktop, turn on host networking.

To run it without Docker, after the setup script:

```sh
npm start
```

`npm start` is `node demo/server.ts`. Node 22.18 or later runs the TypeScript as it is. The library has to be built first (`npm run build`) because the demo imports the package, and the package's entry is `dist/`.

## What you can do

- **Sign in with OpenID Connect.** The button goes to `/login`, which redirects to the provider with `response_type=code` and a PKCE challenge. The provider comes back to `/callback`, and the server answers 303 to `/u/<account>/` so the code is not left in the address bar.
- **Add another account.** That sign-in sends `prompt=login`, so the provider does not silently reuse the first person.
- **Two tabs, two people.** Each account has its own URL. Ending one does not change the other tab.
- **CAEP & RISC events.** The events tab follows this account only. The stream is the application's, polled with a Bearer token from the client-credentials grant (`ssf.manage`). Change the person's password, sign them out at the provider, or disable the account, and the tab updates.
- **Sign out of this account**, or of every account in this browser. That is local. The provider session is left to the CAEP events, and to `endSessionUrl` if you call it yourself.

The home page still loads when the client secret is missing. It says to run the setup script. `/healthz` does not need the provider.

## Configuration

`demo/oidc.json` is the file. `OIDC_CONFIG` points at another one. `OIDC_METADATA_FILE` replaces discovery with a document on disk, which is how the CI smoke test hits `/login` without a provider. `PORT` defaults to 3000. `SESSION_SECRET` seals the cookies; without it, a new secret is chosen at startup and existing cookies stop verifying.

## Without iya-sts

Any OpenID Provider that can register a confidential client works. Point `metadataUrl` at its discovery document, set `client_id`, `clientSecret`, and `redirectUri`, and register the redirect URI `http://localhost:3000/callback`, the response type `code`, and the grants `authorization_code` and `refresh_token`. Add `client_credentials` and the scope `ssf.manage` only if you want the events tab's receiver to run. Remove the `ssf` block to leave the receiver off.
