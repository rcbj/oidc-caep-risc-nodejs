// The client profile of issue #31, point by point, against the stub provider (stub-provider.ts) and
// a stub Shared Signals transmitter that requires DPoP: DPoP with nonces, acr, PAR when the provider
// requires it, the ID token algorithm allow-list, typ and at_hash, the same defaults and redirect
// rule however a client is created, and the per-session token cache.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, describe, it } from 'node:test';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import {
  DEFAULT_ID_TOKEN_SIGNING_ALGS, EVENT, MemoryTokenStore, OidcError, RelyingParty, SignalsReceiver, athOf,
  resolveConfig, trackedFromLogin, type CachedSession, type TokenStore,
} from '../src/index.ts';
import { CLIENT, config, signIn, startProvider, type Stub } from './stub-provider.ts';

const quiet = { info() {}, warn() {}, error() {} };

const rejectsWith = (code: string, pattern: RegExp) => (err: unknown) =>
  err instanceof OidcError && err.code === code && pattern.test(err.message);

describe('the client profile (#31)', { concurrency: 1 }, () => {
  let stub: Stub;
  before(async () => { stub = await startProvider(); });
  after(async () => { await stub.close(); });
  beforeEach(() => { stub.reset(); });

  describe('1. DPoP', () => {
    it('auto: uses DPoP when ES256 is advertised, with a proof at PAR, the token endpoint and UserInfo', async () => {
      stub.dpop = true;
      stub.par = true;
      const rp = await RelyingParty.create(config(stub));
      assert.equal(rp.config.dpop, 'auto');
      assert.equal(rp.usesDpop, true);
      const { login } = await signIn(rp);
      assert.equal(login.tokenType, 'DPoP');
      assert.equal(stub.lastAuthorize?.get('dpop_jkt'), rp.dpopThumbprint);
      const par = stub.proofs.find((p) => p.where === 'par');
      const token = stub.proofs.find((p) => p.where === 'token');
      assert.ok(par && token);
      assert.equal(par.htu, `${stub.url}/par`);
      assert.equal(par.htm, 'POST');
      assert.equal(token.htu, `${stub.url}/token`);
      assert.equal(par.ath, undefined);
      assert.equal(token.jkt, rp.dpopThumbprint);

      const info = await rp.userinfo(login.accessToken, login.subject);
      assert.equal(info.sub, 'user-1');
      const resource = stub.proofs.find((p) => p.where === 'userinfo');
      assert.equal(resource?.ath, athOf(login.accessToken));
      assert.equal(resource?.htm, 'GET');

      // htu carries no query and no fragment.
      const answer = await rp.fetchResource(`${stub.url}/userinfo?x=1#frag`, {}, login);
      assert.equal(answer.status, 200);
      assert.equal(stub.proofs.at(-1)?.htu, `${stub.url}/userinfo`);

      await rp.refresh(login.refreshToken!, { previous: login });
      await rp.clientCredentials('ssf.manage');
      assert.deepEqual(stub.grants, ['authorization_code', 'refresh_token', 'client_credentials']);
      assert.equal(stub.proofs.filter((p) => p.where === 'token').length, 3);
    });

    it('auto: sends no proof when the provider does not advertise DPoP, or not ES256', async () => {
      const plain = await RelyingParty.create(config(stub));
      assert.equal(plain.usesDpop, false);
      const { login } = await signIn(plain);
      assert.equal(login.tokenType, 'Bearer');
      assert.equal(stub.lastAuthorize?.has('dpop_jkt'), false);
      assert.equal(stub.proofs.length, 0);
      stub.dpop = true;
      stub.dpopAlgs = ['RS256'];
      const noEs256 = await RelyingParty.create(config(stub));
      assert.equal(noEs256.usesDpop, false);
      assert.equal((await signIn(noEs256)).login.tokenType, 'Bearer');
    });

    it('always: fails at creation unless ES256 is advertised; never: sends no proofs', async () => {
      await assert.rejects(() => RelyingParty.create(config(stub, { dpop: 'always' })), rejectsWith('discovery', /dpop is always/));
      stub.dpop = true;
      stub.dpopAlgs = ['PS256'];
      await assert.rejects(() => RelyingParty.create(config(stub, { dpop: 'always' })), rejectsWith('discovery', /ES256/));
      stub.dpopAlgs = ['ES256'];
      assert.equal((await RelyingParty.create(config(stub, { dpop: 'always' }))).usesDpop, true);
      const never = await RelyingParty.create(config(stub, { dpop: 'never' }));
      assert.equal(never.usesDpop, false);
      const { login } = await signIn(never);
      assert.equal(login.tokenType, 'Bearer');
      assert.equal(stub.proofs.length, 0);
      await assert.rejects(() => RelyingParty.create(config(stub, { dpop: 'sometimes' as 'auto' })), rejectsWith('config', /dpop must be/));
    });

    it('retries once with the nonce the authorization server and the resource server gave, and keeps it per origin', async () => {
      stub.dpop = true;
      stub.par = true;
      stub.dpopNonce = 'nonce-1';
      const rp = await RelyingParty.create(config(stub));
      const { login } = await signIn(rp);
      // One challenge at PAR; the token endpoint is on the same origin, so its first proof already has the nonce.
      assert.equal(stub.challenges, 1);
      assert.ok(stub.proofs.every((p) => p.nonce === 'nonce-1'));
      stub.dpopNonce = 'nonce-2';
      const info = await rp.userinfo(login.accessToken, login.subject);
      assert.equal(info.sub, 'user-1');
      assert.equal(stub.challenges, 2);
      assert.equal(stub.proofs.at(-1)?.nonce, 'nonce-2');
      assert.equal(stub.proofs.at(-1)?.ath, athOf(login.accessToken));
    });

    it('refuses a token_type that does not match whether a proof was sent', async () => {
      stub.dpop = true;
      stub.tokenType = 'Bearer';
      const rp = await RelyingParty.create(config(stub));
      await assert.rejects(() => signIn(rp), rejectsWith('protocol', /proof was sent.*not DPoP/));
      stub.dpop = false;
      stub.tokenType = 'DPoP';
      const plain = await RelyingParty.create(config(stub));
      await assert.rejects(() => signIn(plain), rejectsWith('protocol', /no DPoP proof.*not Bearer/));
      stub.tokenType = 'bearer';
      assert.equal((await signIn(plain)).login.tokenType, 'bearer');
      stub.dpop = true;
      stub.tokenType = 'dpop';
      assert.equal((await signIn(await RelyingParty.create(config(stub)))).login.tokenType, 'dpop');
    });

    it('takes the DPoP key from dpopKey, and refuses one that is not P-256', async () => {
      stub.dpop = true;
      const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const pem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      const expected = await calculateJwkThumbprint(ec.publicKey.export({ format: 'jwk' }) as JWK, 'sha256');
      const rp = await RelyingParty.create(config(stub, { dpopKeyPem: pem }));
      assert.equal(rp.dpopThumbprint, expected);
      const second = await RelyingParty.create(config(stub, { dpopKeyPem: pem }));
      assert.equal(second.dpopThumbprint, expected);
      const generated = await RelyingParty.create(config(stub));
      assert.notEqual(generated.dpopThumbprint, expected);
      await signIn(rp);
      assert.equal(stub.proofs.at(-1)?.jkt, expected);

      const dir = mkdtempSync(join(tmpdir(), 'oidc-dpop-'));
      writeFileSync(join(dir, 'dpop.pem'), pem);
      const file = { metadataUrl: 'https://localhost:8081/.well-known/openid-configuration', client_id: CLIENT, clientSecret: 's', redirectUri: 'http://localhost:3000/callback' };
      assert.equal(resolveConfig({ ...file, dpopKey: 'file:dpop.pem' }, dir).dpopKeyPem, pem.trim());
      assert.equal(resolveConfig({ ...file, dpop: 'never' }, dir).dpop, 'never');
      const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      await assert.rejects(() => RelyingParty.create(config(stub, { dpopKeyPem: rsa })), rejectsWith('config', /P-256/));
    });
  });

  describe('2. acr', () => {
    it('requires the ID token acr to be one of the requested values, from the setting or the request', async () => {
      const rp = await RelyingParty.create(config(stub, { acrValues: 'urn:acr:a urn:acr:b' }));
      stub.acr = 'urn:acr:b';
      const { request, login } = await signIn(rp);
      assert.deepEqual(request.acrValues, ['urn:acr:a', 'urn:acr:b']);
      assert.equal(stub.lastAuthorize?.get('acr_values'), 'urn:acr:a urn:acr:b');
      assert.equal(login.claims.acr, 'urn:acr:b');
      stub.acr = 'urn:acr:c';
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /not one of the requested acr_values/));
      stub.acr = undefined;
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /no acr/));

      const plain = await RelyingParty.create(config(stub));
      stub.acr = 'urn:acr:c';
      await assert.rejects(() => signIn(plain, { acrValues: 'urn:acr:x' }), rejectsWith('validation', /acr/));
      stub.acr = 'urn:acr:x';
      assert.equal((await signIn(plain, { acrValues: 'urn:acr:x' })).login.claims.acr, 'urn:acr:x');
      // Not requested: not checked.
      stub.acr = undefined;
      assert.equal((await signIn(plain)).request.acrValues, undefined);
    });

    it('does not check acr again on refresh', async () => {
      const rp = await RelyingParty.create(config(stub, { acrValues: 'urn:acr:a' }));
      stub.acr = 'urn:acr:a';
      const { login } = await signIn(rp);
      stub.acr = undefined;
      const refreshed = await rp.refresh(login.refreshToken!, { previous: login });
      assert.equal(refreshed.claims.acr, undefined);
    });
  });

  describe('3. PAR required by the provider', () => {
    it('fails at creation with par never, and pushes with auto', async () => {
      stub.requirePar = true;
      await assert.rejects(() => RelyingParty.create(config(stub, { par: 'never' })), rejectsWith('config', /requires pushed authorization/));
      const rp = await RelyingParty.create(config(stub));
      assert.equal(rp.metadata.require_pushed_authorization_requests, true);
      const { request, login } = await signIn(rp);
      assert.match(request.url, /request_uri=/);
      assert.equal(login.subject, 'user-1');
      stub.requirePar = false;
      await assert.rejects(() => RelyingParty.create(config(stub, { par: 'always' })), rejectsWith('discovery', /no pushed authorization endpoint/));
    });
  });

  describe('4. ID token algorithms', () => {
    it('accepts RS256 only by default, and only what the provider advertises', async () => {
      assert.deepEqual(DEFAULT_ID_TOKEN_SIGNING_ALGS, ['RS256']);
      const rp = await RelyingParty.create(config(stub));
      assert.deepEqual(rp.config.idTokenSigningAlgs, ['RS256']);
      assert.equal((await signIn(rp)).login.subject, 'user-1');
      stub.idTokenAlgs = ['PS256', 'ES256'];
      await assert.rejects(() => RelyingParty.create(config(stub)), rejectsWith('discovery', /none of the allowed/));
      // Widened: only the advertised members of the list count.
      stub.idTokenAlgs = ['ES256'];
      const widened = await RelyingParty.create(config(stub, { idTokenSigningAlgs: ['RS256', 'ES256'] }));
      stub.idTokenAlgs = ['RS256', 'ES256'];
      await assert.rejects(() => signIn(widened), rejectsWith('signature', /RS256/));
      // Pinned keeps its meaning, and must be advertised.
      stub.idTokenAlgs = ['RS256', 'PS256'];
      await assert.rejects(() => RelyingParty.create(config(stub, { idTokenSignedResponseAlg: 'ES256' })), rejectsWith('discovery', /does not advertise/));
      const pinned = await RelyingParty.create(config(stub, { idTokenSignedResponseAlg: 'RS256', idTokenSigningAlgs: ['PS256'] }));
      assert.equal((await signIn(pinned)).login.subject, 'user-1');
    });

    it('never accepts none, and accepts a symmetric algorithm only when it is named', async () => {
      await assert.rejects(() => RelyingParty.create(config(stub, { idTokenSigningAlgs: ['RS256', 'none'] })), rejectsWith('config', /none/));
      await assert.rejects(() => RelyingParty.create(config(stub, { idTokenSignedResponseAlg: 'none' })), rejectsWith('config', /none/));
      const dir = mkdtempSync(join(tmpdir(), 'oidc-algs-'));
      const file = { metadataUrl: 'https://localhost:8081/.well-known/openid-configuration', client_id: CLIENT, clientSecret: 's', redirectUri: 'http://localhost:3000/callback' };
      assert.throws(() => resolveConfig({ ...file, idTokenSigningAlgs: ['None'] }, dir), rejectsWith('config', /none/));
      assert.throws(() => resolveConfig({ ...file, idTokenSigningAlgs: [] }, dir), rejectsWith('config', /non-empty/));
      assert.deepEqual(resolveConfig({ ...file, idTokenSigningAlgs: ['RS256', 'ES256'] }, dir).idTokenSigningAlgs, ['RS256', 'ES256']);

      stub.idTokenAlgs = ['RS256', 'HS256'];
      stub.signAlg = 'HS256';
      const strict = await RelyingParty.create(config(stub));
      await assert.rejects(() => signIn(strict), rejectsWith('signature', /HS256/));
      const named = await RelyingParty.create(config(stub, { idTokenSigningAlgs: ['RS256', 'HS256'] }));
      assert.equal((await signIn(named)).login.subject, 'user-1');
    });
  });

  describe('5. typ and at_hash', () => {
    it('requires typ JWT or application/jwt, and at_hash with an access token, unless relaxed', async () => {
      const rp = await RelyingParty.create(config(stub));
      assert.equal(rp.config.requireIdTokenTypAndAtHash, true);
      stub.typ = 'application/JWT';
      assert.equal((await signIn(rp)).login.subject, 'user-1');
      stub.typ = null;
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /no typ/));
      stub.typ = 'at+jwt';
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /typ is at\+jwt/));
      stub.typ = 'JWT';
      stub.omitAtHash = true;
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /no at_hash/));
      stub.badAtHash = true;
      stub.omitAtHash = false;
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /at_hash does not match/));

      const relaxed = await RelyingParty.create(config(stub, { requireIdTokenTypAndAtHash: false }));
      stub.typ = null;
      stub.omitAtHash = true;
      assert.equal((await signIn(relaxed)).login.subject, 'user-1');
      stub.omitAtHash = false;
      stub.badAtHash = true;
      await assert.rejects(() => signIn(relaxed), rejectsWith('validation', /at_hash does not match/));
      stub.typ = 'at+jwt';
      await assert.rejects(() => signIn(relaxed), rejectsWith('validation', /typ/));
    });
  });

  describe('6. the same checks however a client is created', () => {
    it('fills the defaults on a configuration built by hand', async () => {
      const rp = await RelyingParty.create(config(stub));
      assert.equal(rp.config.par, 'auto');
      assert.equal(rp.config.dpop, 'auto');
      assert.equal(rp.config.clockToleranceSec, 30);
      assert.equal(rp.config.maxIdTokenAgeSec, 600);
      assert.deepEqual(rp.config.idTokenSigningAlgs, ['RS256']);
      assert.equal(rp.config.requireIdTokenTypAndAtHash, true);
      assert.equal(rp.config.privateKeyAlg, 'RS256');
      await assert.rejects(() => RelyingParty.create(config(stub, { clockToleranceSec: -1 })), rejectsWith('config', /clockToleranceSec/));
      await assert.rejects(() => RelyingParty.create(config(stub, { par: 'maybe' as 'auto' })), rejectsWith('config', /par must be/));
    });

    it('holds every redirect URI to https or loopback http, including a per-request one', async () => {
      for (const ok of ['https://app.example/cb', 'http://localhost:3000/cb', 'http://127.0.0.1/cb', 'http://[::1]:3000/cb']) {
        assert.equal((await RelyingParty.create(config(stub, { redirectUri: ok }))).config.redirectUri, ok);
      }
      await assert.rejects(() => RelyingParty.create(config(stub, { redirectUri: 'http://app.example/cb' })), rejectsWith('config', /loopback/));
      await assert.rejects(() => RelyingParty.create(config(stub, { postLogoutRedirectUri: 'http://app.example/' })), rejectsWith('config', /loopback/));
      const dir = mkdtempSync(join(tmpdir(), 'oidc-redirect-'));
      const file = { metadataUrl: 'http://idp.example/.well-known/openid-configuration', client_id: CLIENT, clientSecret: 's', allowInsecure: true };
      assert.throws(() => resolveConfig({ ...file, redirectUri: 'http://app.example/cb' }, dir), rejectsWith('config', /loopback/));
      const rp = await RelyingParty.create(config(stub));
      await assert.rejects(() => rp.authorize({ redirectUri: 'http://app.example/cb' }), rejectsWith('config', /loopback/));
      await assert.rejects(() => rp.authorize({ redirectUri: 'javascript:alert(1)' }), rejectsWith('config', /https/));
      const request = await rp.authorize({ redirectUri: 'https://app.example/other' });
      assert.equal(request.redirectUri, 'https://app.example/other');
    });

    it('refuses an ID token iat beyond the clock tolerance in the future', async () => {
      const rp = await RelyingParty.create(config(stub));
      stub.futureIat = true;
      await assert.rejects(() => signIn(rp), rejectsWith('validation', /iat/));
      const lenient = await RelyingParty.create(config(stub, { clockToleranceSec: 300 }));
      assert.equal((await signIn(lenient)).login.subject, 'user-1');
    });
  });

  describe('7. the per-session token cache', () => {
    it('caches a sign-in under the session the application names, or a handle it returns', async () => {
      const rp = await RelyingParty.create(config(stub));
      const { login } = await signIn(rp, {}, { session: 'local-1' });
      assert.equal(login.session, 'local-1');
      const token = await rp.accessToken('local-1');
      assert.equal(token.accessToken, login.accessToken);
      assert.equal(token.tokenType, 'Bearer');
      assert.ok(token.expiresAt);
      const made = (await signIn(rp)).login;
      assert.ok(made.session && made.session.length >= 20);
      assert.equal((await rp.accessToken(made.session)).accessToken, made.accessToken);
      assert.equal((await rp.sessionTokens('local-1'))?.subject, 'user-1');
      assert.deepEqual(stub.grants, ['authorization_code', 'authorization_code']);
      await rp.removeSession('local-1');
      await assert.rejects(() => rp.accessToken('local-1'), rejectsWith('validation', /no tokens/));
    });

    it('refreshes a token with 30 seconds or less left, with a DPoP proof, and updates the cache', async () => {
      stub.dpop = true;
      stub.expiresIn = 25;
      const rp = await RelyingParty.create(config(stub));
      const { login } = await signIn(rp, {}, { session: 's' });
      stub.expiresIn = 300;
      const [first, second] = await Promise.all([rp.accessToken('s'), rp.accessToken('s')]);
      assert.notEqual(first.accessToken, login.accessToken);
      assert.equal(first.accessToken, second.accessToken);
      assert.equal(first.tokenType, 'DPoP');
      assert.deepEqual(stub.grants, ['authorization_code', 'refresh_token']);
      const refreshProof = stub.proofs.filter((p) => p.where === 'token').at(-1);
      assert.equal(refreshProof?.jkt, rp.dpopThumbprint);
      assert.equal((await rp.accessToken('s')).accessToken, first.accessToken);
      assert.equal(stub.grants.length, 2);
      assert.equal((await rp.sessionTokens('s'))?.accessToken, first.accessToken);
      const info = await rp.userinfo(first.accessToken, login.subject);
      assert.equal(info.sub, 'user-1');
    });

    it('removes the session and refuses when the refresh fails, or there is no refresh token', async () => {
      stub.expiresIn = 10;
      const rp = await RelyingParty.create(config(stub));
      await signIn(rp, {}, { session: 'doomed' });
      stub.refreshFails = true;
      await assert.rejects(() => rp.accessToken('doomed'), (err: unknown) => err instanceof OidcError && err.oauthError === 'invalid_grant');
      assert.equal(await rp.sessionTokens('doomed'), undefined);
      await assert.rejects(() => rp.accessToken('doomed'), rejectsWith('validation', /no tokens/));

      const store = new MemoryTokenStore();
      const bare = await RelyingParty.create(config(stub), { tokenStore: store });
      const { login } = await signIn(bare, {}, { session: 'no-refresh' });
      const cached = store.get('no-refresh')!;
      const { refreshToken: _dropped, ...withoutRefresh } = cached;
      store.set('no-refresh', withoutRefresh);
      assert.ok(login.refreshToken);
      await assert.rejects(() => bare.accessToken('no-refresh'), rejectsWith('protocol', /no refresh token/));
      assert.equal(store.size, 0);
    });

    it('uses a store the application supplies', async () => {
      const calls: string[] = [];
      const rows = new Map<string, string>();
      const shared: TokenStore = {
        async get(session) {
          calls.push(`get ${session}`);
          const row = rows.get(session);
          return row ? JSON.parse(row) as CachedSession : undefined;
        },
        async set(session, tokens) {
          calls.push(`set ${session}`);
          rows.set(session, JSON.stringify(tokens));
        },
        async delete(session) {
          calls.push(`delete ${session}`);
          rows.delete(session);
        },
      };
      const one = await RelyingParty.create(config(stub), { tokenStore: shared });
      const two = await RelyingParty.create(config(stub), { tokenStore: shared });
      const { login } = await signIn(one, {}, { session: 'shared-1' });
      assert.equal((await two.accessToken('shared-1')).accessToken, login.accessToken);
      await two.removeSession('shared-1');
      assert.deepEqual(calls, ['set shared-1', 'get shared-1', 'delete shared-1']);
    });
  });

  describe('DPoP to the Shared Signals transmitter', () => {
    it('calls the transmitter with a DPoP-bound token and proofs, answers its nonce, and ends cached sessions on session-revoked', async () => {
      stub.dpop = true;
      const rp = await RelyingParty.create(config(stub));
      const transmitter = await startTransmitter();
      try {
        const { login } = await signIn(rp, {}, { session: 'local-a' });
        const ended: string[] = [];
        const receiver = new SignalsReceiver({
          transmitter: transmitter.url,
          request: rp.signalsRequest('ssf.manage'),
          relyingParty: rp,
          onEndSessions: (ids) => { ended.push(...ids); },
          pollIntervalMs: 60_000,
          log: quiet,
        });
        await receiver.start();
        receiver.stop();
        assert.equal(transmitter.challenges, 1);
        assert.ok(transmitter.calls.length >= 4);
        for (const call of transmitter.calls) {
          assert.equal(call.scheme, 'DPoP');
          assert.equal(call.jkt, rp.dpopThumbprint);
          assert.equal(call.ath, athOf(call.token));
          assert.equal(call.nonce, 'tx-nonce');
        }
        assert.deepEqual(stub.grants.filter((g) => g === 'client_credentials'), ['client_credentials']);

        await receiver.track(trackedFromLogin('local-a', login));
        transmitter.deliver(EVENT.sessionRevoked, {
          format: 'complex',
          user: { format: 'iss_sub', iss: transmitter.url, sub: login.subject },
          session: { format: 'opaque', id: login.sid },
        });
        await receiver.pollOnce();
        assert.deepEqual(ended, ['local-a']);
        assert.equal(await rp.sessionTokens('local-a'), undefined);

        await signIn(rp, {}, { session: 'local-b' });
        await receiver.untrack('local-b');
        assert.equal(await rp.sessionTokens('local-b'), undefined);
      } finally {
        await transmitter.close();
      }
    });
  });
});

// A transmitter that accepts only a DPoP-bound token with a valid proof (ath, htm, htu) and asks for
// a nonce on the first proof.
async function startTransmitter() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 't1', alg: 'RS256', use: 'sig' };
  const queue = new Map<string, string>();
  const calls: Array<{ scheme: string; token: string; jkt: string; ath?: string; nonce?: string }> = [];
  const streams: Record<string, unknown>[] = [];
  let challenges = 0;
  let base = '';
  const server = http.createServer((req, res) => {
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => {
      void (async () => {
        const out = (status: number, body?: unknown, headers: Record<string, string> = {}) => {
          res.writeHead(status, { 'content-type': 'application/json', ...headers });
          res.end(body === undefined ? '' : JSON.stringify(body));
        };
        const [scheme = '', token = ''] = String(req.headers.authorization ?? '').split(' ');
        const proof = String(req.headers.dpop ?? '');
        if (scheme !== 'DPoP' || !proof) return out(401, { error: 'invalid_token' }, { 'www-authenticate': 'DPoP error="invalid_token"' });
        const header = decodeProtectedHeader(proof) as { jwk: JWK; typ?: string };
        const { payload } = await jwtVerify(proof, await importJWK(header.jwk, 'ES256'), { typ: 'dpop+jwt' });
        const url = new URL(req.url ?? '/', base);
        const ath = createHash('sha256').update(token).digest('base64url');
        if (payload.htm !== req.method || payload.htu !== `${base}${url.pathname}` || payload.ath !== ath) {
          return out(401, { error: 'invalid_dpop_proof' }, { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' });
        }
        if (payload.nonce !== 'tx-nonce') {
          challenges += 1;
          return out(401, { error: 'use_dpop_nonce' }, { 'www-authenticate': 'DPoP error="use_dpop_nonce"', 'dpop-nonce': 'tx-nonce' });
        }
        calls.push({ scheme, token, jkt: await calculateJwkThumbprint(header.jwk, 'sha256'), ath: String(payload.ath), nonce: String(payload.nonce) });
        if (url.pathname === '/.well-known/ssf-configuration') {
          return out(200, {
            issuer: base, jwks_uri: `${base}/jwks`, configuration_endpoint: `${base}/ssf/stream`,
            delivery_methods_supported: ['urn:ietf:rfc:8936'],
          });
        }
        if (url.pathname === '/jwks') return out(200, { keys: [jwk] });
        if (url.pathname === '/ssf/stream' && req.method === 'GET') return out(200, streams);
        if (url.pathname === '/ssf/stream' && req.method === 'POST') {
          const stream = { stream_id: 's1', iss: base, aud: 'my-app', delivery: { method: 'urn:ietf:rfc:8936', endpoint_url: `${base}/ssf/poll/s1` }, events_delivered: [] };
          streams.push(stream);
          return out(201, stream);
        }
        if (url.pathname === '/ssf/poll/s1') {
          const body = JSON.parse(text || '{}') as { ack?: string[] };
          for (const jti of body.ack ?? []) queue.delete(jti);
          return out(200, { sets: Object.fromEntries(queue), moreAvailable: false });
        }
        return out(404, { error: 'not_found' });
      })().catch((err: Error) => {
        res.writeHead(500);
        res.end(err.message);
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url: base,
    calls,
    get challenges() { return challenges; },
    deliver(type: string, subId: object) {
      const jti = randomUUID();
      const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 't1', typ: 'secevent+jwt' })).toString('base64url');
      const p = Buffer.from(JSON.stringify({ iss: base, aud: 'my-app', jti, iat: Math.floor(Date.now() / 1000), sub_id: subId, events: { [type]: {} } })).toString('base64url');
      queue.set(jti, `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`);
      return jti;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
