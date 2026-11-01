# Handling CAEP and RISC events

A server-side application has one Shared Signals stream for everyone who uses it. The receiver polls that stream, verifies each Security Event Token, and tells the application which of its own sessions the event is about. The browser never sees the transmitter, and it never holds the token the receiver authenticates with.

The default is on. `signals: false` turns CAEP and RISC off, drops `ssf.read` and `ssf.manage` from the authorization request, and does not contact a transmitter. The receiver below is not started. A caller who constructs `SignalsReceiver` has opted in.

The event type URIs are the same ones [oidc-caep-client](https://github.com/rcbj/oidc-caep-client) uses. CAEP events are about sessions. RISC events are about accounts. SSF's own two events are about the stream.

## What the receiver ends

By default these end the local sessions they name:

| Event | Why the session ends |
|---|---|
| `session-revoked` | That provider session was revoked. Only the local sessions with that `sid` end. |
| `sessions-revoked` | Every session of that account was revoked. |
| `account-disabled` | The account can no longer sign in. |
| `account-purged` | The account was deleted. |
| `credential-compromise` | A credential of that account was compromised. |

Anything else is delivered to `on` and left in place. `credential-change` is recorded and does not end the session. `verification` and `stream-updated` name no person.

Pass `endOn` to choose a different set. The URIs are on `EVENT` in [the reference](../README.md).

## Authentication

iya-sts accepts a Bearer token on `/ssf` when the token's scope includes `ssf.manage` and the application holds the `SSF_MANAGE` role. `ssf.manage` covers read. The token is the application's, from the client-credentials grant, not a person's access token:

```ts
import { RelyingParty, SignalsReceiver, trackedFromLogin } from 'oidc-caep-risc-nodejs';

const rp = await RelyingParty.fromFile('oidc.json');
const receiver = new SignalsReceiver({
  transmitter: 'https://idp.example',
  tls: rp.tls(),
  headers: async () => {
    const creds = await rp.clientCredentials('ssf.manage');
    return { authorization: `Bearer ${creds.accessToken}` };
  },
  description: 'app',
  onEndSessions: async (ids, event) => {
    for (const id of ids) await sessions.end(id);
  },
});
receiver.on('*', (event) => log(event));
await receiver.start();
```

The grant has to be registered on the client, next to `authorization_code` and `refresh_token`. The setup script does that. A `DPoP` token is refused: this client sends Bearer tokens.

Mutual TLS is the other way in. Pass `cert` and `key` on `tls` and omit `headers`. The demo uses the Bearer token, because the confidential client already has a secret and iya-sts will mint the application token.

## After each sign-in

```ts
await receiver.track(trackedFromLogin(localId, login, expiresAt));
```

That records the subject's `sub` as the person, the email, and the ID token `sid` as the provider session. `session-revoked` matches the provider session. The account events match the person, then the email. `untrack` after a local sign-out.

## Handlers

```ts
receiver.on(EVENT.credentialChange, (event) => {
  // event.payload is the event's own members. event.sessions are the local ids.
});
```

A handler that throws is logged. The SET is still acknowledged, so a bug in a handler does not make the transmitter redeliver forever. `onEndSessions` is the same: if it throws, the receiver logs it and still acknowledges.

## The stream

`start` reads `/.well-known/ssf-configuration` (the issuer path with the well-known segment inserted, then the same path appended), loads the JWKS, and uses this application's poll stream or creates one. `verify(state)` asks the transmitter for a verification event. The demo shows that event only on the account that asked.

Polls do not overlap. A signature that does not verify is reported back as `invalid_key` on the next poll, after one refresh of the JWKS. The poll timer does not keep the process alive.
