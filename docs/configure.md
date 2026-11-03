---
title: Setting up iya-sts
---

# Setting up iya-sts

`scripts/configure-iya-sts.ts` registers the demo as a confidential client of a running [iya-sts](https://rcbj.github.io/iya-sts/). It talks to the management API of the realm the configuration's `metadataUrl` names (`https://localhost:8081` for the file in the repository).

```sh
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
node scripts/configure-iya-sts.ts --dry-run
```

The token is minted the way iya-sts's own tools mint one: the seeded client `sts-api-client`, grant `client_credentials`, HTTP Basic, audience `<base>/admin-api`, scope `admin:read admin:write`. The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. On a compose stack that secret is in OpenBao; iya-sts's management API docs say how to read it.

## What it registers

The application id is the file's `client_id` (`oidc-caep-risc-demo`). The protocols are `oauth2` and `oidc`. The fields are:

| Field | Value |
|---|---|
| `oauthRedirectUri` | the file's `redirectUri`. A loopback URI is registered on the port the demo is listening on |
| `oauthPostLogoutRedirectUri` | the file's `postLogoutRedirectUri`, moved the same way |
| `oauthResponseType` | `code` |
| `oauthGrantType` | `authorization_code`, `refresh_token`, `client_credentials` |
| `oauthAllowedScope` | the file's scopes, the same string oidc-caep-client uses |
| `oauthTokenEndpointAuthMethod` | `client_secret_basic` |
| `oauthIdTokenSignedResponseAlg` | `RS256`, the library's default ID token allow-list |
| `oauthClientSecret` | a new 32-byte secret, only when the application is created |

No browser origin is registered. This client is a server.

The client-credentials grant is there so the demo can take its own access token for the Shared Signals stream. The script adds the application to `SSF_READ` and `SSF_MANAGE` for whichever of `ssf.read` and `ssf.manage` the scopes name. iya-sts issues `ssf.read` only when the person is in the group `ssf-read` and the application holds `SSF_READ`; `ssf.manage` the same way through `ssf-manage` and `SSF_MANAGE`.

When the configuration sets `signals` to `false`, those two scopes are ignored even if the file still lists them. The script does not add the application to `SSF_READ` or `SSF_MANAGE`, and it does not put the test user in `ssf-read` or `ssf-manage`. It does not register a transmitter. The default is on, which is what `demo/oidc.json` leaves in place.

It also turns on `authn.multipleAccounts`, so one browser can hold several signed-in people. Without that, iya-sts ends the first person's session when the next one signs in, and the CAEP event ends that account in the demo.

## The secret, and running it again

The secret is written to `demo/generated/client-secret` (created mode 0600, and never printed: a dry run's plan does not hold it) only when that file is missing and the application is created now. A later run adds redirect URIs, grants, and scopes that are missing. It does not send a new secret.

If the application already exists and the secret file is missing, the script stops. It will not rotate the secret out from under a deployment that still has the old one.

## The test user

The user is `oidc-demo-user` (pass `--test-user` to choose another, or `--no-test-user` to skip). The attributes are `cn`, `givenName`, `sn`, `displayName`, and `mail`, which is what a product-mode realm requires. The password is `OIDC_DEMO_USER_PASSWORD`, or iya-sts generates one; the script writes a generated one to `demo/generated/oidc-demo-user.password` (created mode 0600) and prints only that path, never the password. An existing user keeps its password unless that variable is set. The user is added to `ssf-read` and `ssf-manage`.

This is a different user from oidc-caep-client's `caep-demo-user` and from saml2-sp-nodejs's `saml-demo-user`.

## TLS

`tlsCa` in the configuration is the CA trust chain for the STS listener certificate. The demo's file names `demo/generated/idp-ca.pem`. Every run rewrites that file from `GET /tls/server-certificate`: the listener certificate, the intermediates, and the root. That is the bundle iya-sts tells a client to trust. The first fetch does not verify TLS, because there is nothing to verify it against until the file exists. If that document is not served, the script saves the chain the handshake presented instead. The demo image build copies that file in (`COPY demo demo`; `.dockerignore` admits only it from `demo/generated`), so rebuild the image after running the script against a different iya-sts.

The script prints the trust anchor's SHA-256 fingerprint. Compare it with the Root CA on iya-sts's Server configuration, PKI page. A certified listener certificate on its own is not an anchor: the chain has to include the root that signed it. Later calls trust this file in addition to node's own store.

## Options

| Option | |
|---|---|
| `--config` | Default `demo/oidc.json`. |
| `--idp` | iya-sts's base, or `/realm/<id>` for a trust realm. Default: the origin of `metadataUrl`, or `IYA_STS_URL`. |
| `--public-url` | Replaces the origin of the redirect URIs and keeps their paths. Without it, a loopback redirect follows the running demo's `PORT`, then `$PORT`. |
| `--dry-run` | Print the calls. Nothing is sent, and no secret is written. |
