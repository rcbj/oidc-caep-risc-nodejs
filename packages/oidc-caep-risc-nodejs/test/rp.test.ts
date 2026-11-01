// The confidential client against a stub OpenID Provider: discovery, Authorization Code with PKCE,
// client authentication, ID token checks, refresh, client credentials, and pushed authorization.
// The stub signs ID tokens with node:crypto, and the client verifies them with jose.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { importSPKI, jwtVerify } from 'jose';
import { DEFAULT_SCOPES, OidcError, RelyingParty, hashClaim, resolveConfig, type ResolvedConfig } from '../src/index.ts';

const CLIENT = 'oidc-caep-risc-demo';
const SECRET = 'test-secret';
const SCOPES = 'openid profile email offline_access ssf.read ssf.manage';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'RS256', use: 'sig' };
const clientKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const clientPem = clientKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const clientSpki = clientKeys.publicKey.export({ type: 'spki', format: 'pem' }) as string;

function atHash(value: string): string {
  const digest = createHash('sha256').update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

function idToken(payload: object, corrupt = false): string {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'op', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  let sig = sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url');
  if (corrupt) sig = `${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
  return `${h}.${p}.${sig}`;
}

interface Issued {
  sub: string;
  email: string;
  sid: string;
  nonce: string;
}

interface Stub {
  url: string;
  par: boolean;
  corrupt: boolean;
  aud: string;
  exp?: number;
  badAtHash: boolean;
  close(): Promise<void>;
}

async function startProvider(): Promise<Stub> {
  const codes = new Map<string, Issued & { redirect: string; challenge: string }>();
  const refresh = new Map<string, Issued>();
  const access = new Map<string, Record<string, unknown>>();
  const pushed = new Map<string, URLSearchParams>();
  const stub = { url: '', par: false, corrupt: false, aud: CLIENT, badAtHash: false, exp: undefined as number | undefined };
  let clientPublic: CryptoKey | undefined;

  const metadata = () => ({
    issuer: stub.url,
    authorization_endpoint: `${stub.url}/authorize`,
    token_endpoint: `${stub.url}/token`,
    jwks_uri: `${stub.url}/jwks`,
    userinfo_endpoint: `${stub.url}/userinfo`,
    end_session_endpoint: `${stub.url}/end-session`,
    ...(stub.par ? { pushed_authorization_request_endpoint: `${stub.url}/par` } : {}),
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    scopes_supported: SCOPES.split(' '),
  });

  function tokenFor(row: Issued): Record<string, unknown> {
    const accessToken = randomBytes(16).toString('hex');
    const refreshToken = randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: stub.url,
      sub: row.sub,
      aud: stub.aud,
      exp: stub.exp ?? now + 300,
      iat: stub.exp ? stub.exp : now,
      nonce: row.nonce,
      email: row.email,
      name: 'Demo User',
      preferred_username: row.sub,
      sid: row.sid,
      at_hash: stub.badAtHash ? 'aaaa' : atHash(accessToken),
    };
    const token = idToken(payload, stub.corrupt);
    refresh.set(refreshToken, row);
    access.set(accessToken, payload);
    stub.aud = CLIENT;
    stub.corrupt = false;
    stub.badAtHash = false;
    stub.exp = undefined;
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      refresh_token: refreshToken,
      id_token: token,
      scope: SCOPES,
    };
  }

  async function authorized(req: http.IncomingMessage, body: string): Promise<boolean> {
    const header = String(req.headers.authorization ?? '');
    if (header.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      return decoded === `${encodeURIComponent(CLIENT)}:${encodeURIComponent(SECRET)}` || decoded === `${CLIENT}:${SECRET}`;
    }
    const params = new URLSearchParams(body);
    if (params.get('client_secret')) return params.get('client_id') === CLIENT && params.get('client_secret') === SECRET;
    const assertion = params.get('client_assertion');
    if (!assertion) return false;
    clientPublic ??= await importSPKI(clientSpki, 'RS256');
    try {
      const verified = await jwtVerify(assertion, clientPublic, { issuer: CLIENT, audience: stub.url, subject: CLIENT });
      return verified.payload.sub === CLIENT;
    } catch {
      return false;
    }
  }

  const server = http.createServer((req, res) => {
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => {
      void (async () => {
        const url = new URL(req.url ?? '/', stub.url);
        const json = (status: number, body: unknown) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(body));
        };
        if (url.pathname === '/.well-known/openid-configuration') return json(200, metadata());
        if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
        if (url.pathname === '/userinfo') {
          const token = String(req.headers.authorization ?? '').replace(/^Bearer /, '');
          const claims = access.get(token);
          return claims ? json(200, claims) : json(401, { error: 'invalid_token' });
        }
        if (url.pathname === '/par' && req.method === 'POST') {
          if (!await authorized(req, text)) return json(401, { error: 'invalid_client' });
          const params = new URLSearchParams(text);
          const requestUri = `urn:par:${randomBytes(8).toString('hex')}`;
          pushed.set(requestUri, params);
          return json(201, { request_uri: requestUri, expires_in: 60 });
        }
        if (url.pathname === '/authorize') {
          const stored = url.searchParams.get('request_uri');
          const params = stored ? pushed.get(stored) : url.searchParams;
          if (!params) return json(400, { error: 'invalid_request' });
          const redirect = params.get('redirect_uri') ?? '';
          const state = params.get('state') ?? '';
          const challenge = params.get('code_challenge') ?? '';
          if (params.get('code_challenge_method') !== 'S256' || !challenge) return json(400, { error: 'invalid_request' });
          const row: Issued = { sub: 'user-1', email: 'user-1@example.com', sid: 'sid-1', nonce: params.get('nonce') ?? '' };
          const code = randomBytes(16).toString('hex');
          codes.set(code, { ...row, redirect, challenge });
          const back = new URL(redirect);
          back.searchParams.set('code', code);
          back.searchParams.set('state', state);
          back.searchParams.set('iss', stub.url);
          res.writeHead(302, { location: back.href });
          res.end();
          return;
        }
        if (url.pathname === '/token' && req.method === 'POST') {
          if (!await authorized(req, text)) return json(401, { error: 'invalid_client', error_description: 'client authentication failed' });
          const params = new URLSearchParams(text);
          if (params.get('grant_type') === 'client_credentials') {
            return json(200, { access_token: 'cc-token', token_type: 'Bearer', expires_in: 120, scope: params.get('scope') });
          }
          if (params.get('grant_type') === 'refresh_token') {
            const row = refresh.get(params.get('refresh_token') ?? '');
            if (!row) return json(400, { error: 'invalid_grant' });
            const minted = tokenFor(row);
            return json(200, { ...minted, id_token: idToken({ ...access.get(String(minted.access_token)), nonce: undefined }) });
          }
          const code = params.get('code') ?? '';
          const row = codes.get(code);
          if (!row) return json(400, { error: 'invalid_grant' });
          if (params.get('redirect_uri') !== row.redirect) return json(400, { error: 'invalid_grant' });
          const verifier = params.get('code_verifier') ?? '';
          const got = createHash('sha256').update(verifier).digest('base64url');
          if (got !== row.challenge) return json(400, { error: 'invalid_grant', error_description: 'pkce' });
          codes.delete(code);
          return json(200, tokenFor(row));
        }
        json(404, { error: 'not_found' });
      })().catch((err: Error) => {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end(err.message);
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  stub.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return Object.assign(stub, { close: () => new Promise<void>((resolve) => server.close(() => resolve())) });
}

function config(stub: Stub, over: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    metadataUrl: `${stub.url}/.well-known/openid-configuration`,
    clientId: CLIENT,
    clientSecret: SECRET,
    tokenEndpointAuthMethod: 'client_secret_basic',
    redirectUri: `http://127.0.0.1/callback`,
    postLogoutRedirectUri: `http://127.0.0.1/`,
    scopes: SCOPES,
    privateKeyAlg: 'RS256',
    par: 'auto',
    clockToleranceSec: 30,
    maxIdTokenAgeSec: 600,
    allowInsecure: true,
    ...over,
  };
}

async function signIn(rp: RelyingParty, options: Parameters<RelyingParty['authorize']>[0] = {}) {
  const request = await rp.authorize(options);
  const response = await fetch(request.url, { redirect: 'manual' });
  const location = response.headers.get('location');
  assert.ok(location, `the provider did not redirect (${response.status})`);
  const query = new URL(location).searchParams;
  const login = await rp.complete(query, request);
  return { request, query, login };
}

describe('a confidential Authorization Code client', { concurrency: 1 }, () => {
  let stub: Stub;
  before(async () => { stub = await startProvider(); });
  after(async () => { await stub.close(); });

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
    assert.equal(own.accessToken, 'cc-token');
    const again = await rp.clientCredentials('ssf.manage');
    assert.equal(again.accessToken, 'cc-token');
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
});
