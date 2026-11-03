// The confidential client against a stub OpenID Provider: discovery, Authorization Code with PKCE,
// client authentication, ID token checks, refresh, client credentials, and pushed authorization.
// The stub (stub-provider.ts) signs ID tokens with node:crypto, and the client verifies them with jose.

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, describe, it } from 'node:test';
import { DEFAULT_SCOPES, OidcError, RelyingParty, hashClaim, resolveConfig } from '../src/index.ts';
import { CLIENT, SCOPES, atHash, clientPem, config, signIn, startProvider, type Stub } from './stub-provider.ts';

describe('a confidential Authorization Code client', { concurrency: 1 }, () => {
  let stub: Stub;
  before(async () => { stub = await startProvider(); });
  after(async () => { await stub.close(); });
  beforeEach(() => { stub.reset(); });

  it('asks for the same scopes as oidc-caep-client, and hashes at_hash the way the specification does', () => {
    assert.equal(DEFAULT_SCOPES, SCOPES);
    assert.equal(hashClaim('abc', 'RS256'), atHash('abc'));
  });

  it('signs in with PKCE, a client secret, and a verified ID token', async () => {
    const rp = await RelyingParty.create(config(stub));
    const { request, login } = await signIn(rp);
    assert.equal(login.subject, 'user-1');
    assert.equal(login.email, 'user-1@example.com');
    assert.equal(login.sid, 'sid-1');
    assert.equal(login.issuer, stub.url);
    assert.equal(login.preferredUsername, 'user-1');
    assert.ok(login.refreshToken);
    assert.match(request.url, /code_challenge=/);
    assert.match(request.url, /code_challenge_method=S256/);
    assert.doesNotMatch(request.url, /client_secret/);
    const info = await rp.userinfo(login.accessToken, login.subject);
    assert.equal(info.sub, 'user-1');
    const end = rp.endSessionUrl({ idToken: login.idToken, state: 'bye' });
    assert.ok(end?.includes('/end-session'));
    assert.ok(end?.includes('id_token_hint='));
    assert.ok(end?.includes('client_id='));
  });

  it('refuses a callback that is not this sign-in', async () => {
    const rp = await RelyingParty.create(config(stub));
    const request = await rp.authorize();
    const response = await fetch(request.url, { redirect: 'manual' });
    const query = new URL(response.headers.get('location') ?? '').searchParams;
    await assert.rejects(() => rp.complete(query, { ...request, state: 'nope' }), /state/);
    await assert.rejects(() => rp.complete(query, { ...request, nonce: 'nope' }), /nonce/);
    query.set('iss', 'https://elsewhere.example');
    await assert.rejects(() => rp.complete(query, request), /iss mismatch/);
    query.set('iss', stub.url);
    query.set('access_token', 'should-not-be-here');
    await assert.rejects(() => rp.complete(query, request), /access_token/);
  });

  it('accepts a code once', async () => {
    const rp = await RelyingParty.create(config(stub));
    const { query, request, login } = await signIn(rp);
    assert.equal(login.subject, 'user-1');
    await assert.rejects(() => rp.complete(query, request), /already used/);
  });

  it('refuses the wrong client secret, a bad signature, the wrong audience, a stale token, and a bad at_hash', async () => {
    const rp = await RelyingParty.create(config(stub));
    const wrong = await RelyingParty.create(config(stub, { clientSecret: 'nope' }));
    const request = await wrong.authorize();
    const response = await fetch(request.url, { redirect: 'manual' });
    const query = new URL(response.headers.get('location') ?? '').searchParams;
    await assert.rejects(() => wrong.complete(query, request), (err: OidcError) => err.oauthError === 'invalid_client');

    stub.corrupt = true;
    await assert.rejects(() => signIn(rp), /signature/);
    stub.aud = 'other-client';
    await assert.rejects(() => signIn(rp), /audience|aud/i);
    stub.exp = Math.floor(Date.now() / 1000) - 3600;
    await assert.rejects(() => signIn(rp), /exp|timestamp|old|iat/i);
    stub.badAtHash = true;
    await assert.rejects(() => signIn(rp), /at_hash/);
  });

  it('refreshes, and takes a client-credentials token for the application itself', async () => {
    const rp = await RelyingParty.create(config(stub));
    const { login } = await signIn(rp);
    const refreshed = await rp.refresh(login.refreshToken!, { previous: login });
    assert.equal(refreshed.subject, login.subject);
    assert.notEqual(refreshed.accessToken, login.accessToken);
    const own = await rp.clientCredentials('ssf.manage');
    assert.match(own.accessToken, /^cc-/);
    assert.equal(own.tokenType, 'Bearer');
    const again = await rp.clientCredentials('ssf.manage');
    assert.equal(again.accessToken, own.accessToken);
    assert.deepEqual(stub.grants.filter((grant) => grant === 'client_credentials'), ['client_credentials']);
  });

  it('posts the authorization request when the provider offers PAR', async () => {
    stub.par = true;
    const rp = await RelyingParty.create(config(stub));
    const { request, login } = await signIn(rp);
    assert.match(request.url, /request_uri=/);
    assert.doesNotMatch(request.url, /code_challenge=/);
    assert.equal(login.subject, 'user-1');
    stub.par = false;
  });

  it('authenticates with client_secret_post and with private_key_jwt', async () => {
    const posted = await RelyingParty.create(config(stub, { tokenEndpointAuthMethod: 'client_secret_post' }));
    assert.equal((await signIn(posted)).login.subject, 'user-1');
    const jwt = await RelyingParty.create(config(stub, {
      tokenEndpointAuthMethod: 'private_key_jwt',
      clientSecret: undefined,
      privateKeyPem: clientPem,
    }));
    assert.equal((await signIn(jwt)).login.subject, 'user-1');
  });

  it('reads a configuration file the way oidc-caep-client names its fields', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oidc-config-'));
    writeFileSync(join(dir, 'secret'), 'from-file\n');
    process.env.OIDC_TEST_SECRET = 'from-env';
    const file = {
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      client_id: CLIENT,
      clientSecret: 'env:OIDC_TEST_SECRET',
      redirectUri: 'http://localhost:3000/callback',
      scopes: SCOPES.split(' '),
    };
    const env = resolveConfig(file, dir);
    assert.equal(env.clientId, CLIENT);
    assert.equal(env.clientSecret, 'from-env');
    assert.equal(env.issuer, 'https://localhost:8081');
    assert.equal(env.scopes, SCOPES);
    assert.equal(env.tokenEndpointAuthMethod, 'client_secret_basic');
    const fromFile = resolveConfig({ ...file, clientSecret: 'file:secret' }, dir);
    assert.equal(fromFile.clientSecret, 'from-file');
    const chain = '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n';
    writeFileSync(join(dir, 'ca.pem'), chain);
    assert.equal(resolveConfig({ ...file, tlsCa: 'ca.pem' }, dir).tlsCa, chain);
    assert.equal(resolveConfig({ ...file, tlsCa: 'file:ca.pem' }, dir).tlsCa, chain);
    assert.equal(resolveConfig({ ...file, tlsCa: chain }, dir).tlsCa, chain.trim());
    process.env.OIDC_TEST_CA = chain;
    assert.equal(resolveConfig({ ...file, tlsCa: 'env:OIDC_TEST_CA' }, dir).tlsCa, chain);
    delete process.env.OIDC_TEST_CA;
    assert.equal(resolveConfig({ ...file, tlsCa: 'env:OIDC_TEST_CA' }, dir).tlsCa, undefined);
    assert.equal(resolveConfig({ ...file, tlsCa: 'missing.pem' }, dir).tlsCa, undefined);
    assert.throws(() => resolveConfig({ ...file, tokenEndpointAuthMethod: 'none' }, dir), /public client/);
    assert.throws(() => resolveConfig({ ...file, scopes: 'profile email' }, dir), /openid/);
    delete process.env.OIDC_TEST_SECRET;
  });

  it('resolves a transmitter unless signals is false, and then drops the Shared Signals scopes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oidc-signals-'));
    const file = {
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      client_id: CLIENT,
      clientSecret: 'secret',
      redirectUri: 'http://localhost:3000/callback',
      ssf: { transmitter: 'https://localhost:8081/', pollIntervalMs: 3000 },
    };
    const omitted = resolveConfig(file, dir);
    assert.equal(omitted.scopes, SCOPES);
    assert.equal('signals' in omitted, false);
    assert.deepEqual(omitted.ssf, { transmitter: 'https://localhost:8081', pollIntervalMs: 3000 });
    const explicit = resolveConfig({ ...file, signals: true, scopes: SCOPES }, dir);
    assert.equal(explicit.scopes, SCOPES);
    assert.equal('signals' in explicit, false);
    assert.deepEqual(explicit.ssf, omitted.ssf);

    const listed = resolveConfig({
      ...file,
      signals: false,
      scopes: `${SCOPES}`,
      ssf: { transmitter: 'not-a-url' },
    }, dir);
    assert.equal(listed.signals, false);
    assert.equal(listed.ssf, undefined);
    assert.equal(listed.scopes, 'openid profile email offline_access');
    assert.equal(listed.scopes.split(/\s+/).includes('ssf.read'), false);
    assert.equal(listed.scopes.split(/\s+/).includes('ssf.manage'), false);

    const defaults = resolveConfig({ ...file, signals: false }, dir);
    assert.equal(defaults.signals, false);
    assert.equal(defaults.ssf, undefined);
    assert.equal(defaults.scopes, 'openid profile email offline_access');
    assert.equal(defaults.scopes.split(/\s+/).includes('openid'), true);

    assert.throws(() => resolveConfig({ ...file, signals: false, scopes: 'ssf.read ssf.manage' }, dir), /openid/);
    assert.throws(
      () => resolveConfig({ ...file, signals: 'no' }, dir),
      (err: unknown) => err instanceof OidcError && err.code === 'config' && err.message === 'signals must be true or false',
    );
  });
});
