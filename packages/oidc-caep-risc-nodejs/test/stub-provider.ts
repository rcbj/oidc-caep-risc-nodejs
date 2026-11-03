// A stub OpenID Provider for the relying-party tests: discovery, PAR, the authorization endpoint,
// the token endpoint (code, refresh and client-credentials grants), UserInfo, and DPoP (RFC 9449)
// with nonces. It signs ID tokens with node:crypto; the client verifies them with jose. Every switch
// on the stub is a property a test sets; reset() puts them all back.

import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, importSPKI, jwtVerify, type JWK } from 'jose';
import type { RelyingParty, RelyingPartyConfig } from '../src/index.ts';

export const CLIENT = 'oidc-caep-risc-demo';
export const SECRET = 'test-secret';
export const SCOPES = 'openid profile email offline_access ssf.read ssf.manage';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'RS256', use: 'sig' };
const clientKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const clientPem = clientKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const clientSpki = clientKeys.publicKey.export({ type: 'spki', format: 'pem' }) as string;

export function atHash(value: string): string {
  const digest = createHash('sha256').update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

/** An ID token: RS256 with the provider's key, or HS256 with the client secret. */
export function idToken(payload: object, options: { corrupt?: boolean; typ?: string | null; alg?: 'RS256' | 'HS256' } = {}): string {
  const alg = options.alg ?? 'RS256';
  const typ = options.typ === undefined ? 'JWT' : options.typ;
  const header = { alg, ...(alg === 'RS256' ? { kid: 'op' } : {}), ...(typ === null ? {} : { typ }) };
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  let sig = alg === 'HS256'
    ? createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url')
    : sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url');
  if (options.corrupt) sig = `${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
  return `${h}.${p}.${sig}`;
}

/** One DPoP proof the stub accepted, as it was presented. */
export interface SeenProof {
  where: string;
  htm: string;
  htu: string;
  jkt: string;
  nonce?: string;
  ath?: string;
}

interface Issued {
  sub: string;
  email: string;
  sid: string;
  nonce: string;
  acr?: string;
}

const PERSISTENT = {
  par: false,
  requirePar: false,
  /** Advertise DPoP (dpop_signing_alg_values_supported). */
  dpop: false,
  dpopAlgs: ['ES256', 'RS256'] as string[],
  /** When set, every DPoP proof must carry this nonce; a proof without it gets a use_dpop_nonce challenge. */
  dpopNonce: undefined as string | undefined,
  /** Overrides the token_type the token endpoint answers. */
  tokenType: undefined as string | undefined,
  /** The acr the ID token carries. */
  acr: undefined as string | undefined,
  /** The header typ: a string, or null for none. */
  typ: 'JWT' as string | null,
  omitAtHash: false,
  futureIat: false,
  signAlg: 'RS256' as 'RS256' | 'HS256',
  idTokenAlgs: ['RS256', 'PS256', 'ES256'] as string[],
  /** The access token lifetime, in seconds. */
  expiresIn: 300,
  refreshFails: false,
};

export type Stub = typeof PERSISTENT & {
  url: string;
  corrupt: boolean;
  aud: string;
  exp?: number;
  badAtHash: boolean;
  /** Every DPoP proof accepted, in order. */
  proofs: SeenProof[];
  /** The parameters of the last authorization request (from PAR or the query). */
  lastAuthorize?: URLSearchParams;
  /** The token requests, by grant type. */
  grants: string[];
  /** How many use_dpop_nonce challenges the stub answered. */
  challenges: number;
  reset(): void;
  close(): Promise<void>;
};

export async function startProvider(): Promise<Stub> {
  const codes = new Map<string, Issued & { redirect: string; challenge: string; jkt?: string }>();
  const refresh = new Map<string, Issued>();
  const access = new Map<string, { claims: Record<string, unknown>; jkt?: string }>();
  const pushed = new Map<string, URLSearchParams>();
  const usedJtis = new Set<string>();
  const stub = {
    url: '', corrupt: false, aud: CLIENT, badAtHash: false, exp: undefined as number | undefined,
    proofs: [] as SeenProof[], grants: [] as string[], challenges: 0, lastAuthorize: undefined as URLSearchParams | undefined,
    ...structuredClone(PERSISTENT),
  } as Stub;
  stub.reset = () => {
    Object.assign(stub, structuredClone(PERSISTENT));
    stub.proofs = [];
    stub.grants = [];
    stub.challenges = 0;
  };
  let clientPublic: CryptoKey | undefined;

  const metadata = () => ({
    issuer: stub.url,
    authorization_endpoint: `${stub.url}/authorize`,
    token_endpoint: `${stub.url}/token`,
    jwks_uri: `${stub.url}/jwks`,
    userinfo_endpoint: `${stub.url}/userinfo`,
    end_session_endpoint: `${stub.url}/end-session`,
    ...(stub.par || stub.requirePar ? { pushed_authorization_request_endpoint: `${stub.url}/par` } : {}),
    ...(stub.requirePar ? { require_pushed_authorization_requests: true } : {}),
    ...(stub.dpop ? { dpop_signing_alg_values_supported: stub.dpopAlgs } : {}),
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: stub.idTokenAlgs,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    scopes_supported: SCOPES.split(' '),
  });

  /**
   * Checks a DPoP proof. Returns its thumbprint, `undefined` when none was sent, or a string starting
   * with `!` naming what is wrong. A missing or stale nonce is `!nonce`.
   */
  async function proofOf(req: http.IncomingMessage, where: string, accessToken?: string): Promise<string | undefined> {
    const proof = req.headers.dpop;
    if (proof === undefined) return undefined;
    if (typeof proof !== 'string') return '!several proofs';
    try {
      const header = decodeProtectedHeader(proof) as Record<string, unknown>;
      if (header.typ !== 'dpop+jwt') return '!typ';
      if (header.alg !== 'ES256') return '!alg';
      const key = header.jwk as JWK;
      if (!key || 'd' in key) return '!jwk';
      const { payload } = await jwtVerify(proof, await importJWK(key, 'ES256'), { typ: 'dpop+jwt' });
      const htu = `${stub.url}${new URL(req.url ?? '/', stub.url).pathname}`;
      if (payload.htm !== req.method) return '!htm';
      if (payload.htu !== htu) return '!htu';
      if (typeof payload.iat !== 'number' || Math.abs(payload.iat - Date.now() / 1000) > 60) return '!iat';
      if (typeof payload.jti !== 'string' || usedJtis.has(payload.jti)) return '!jti';
      usedJtis.add(payload.jti);
      if (accessToken !== undefined) {
        if (payload.ath !== createHash('sha256').update(accessToken).digest('base64url')) return '!ath';
      } else if (payload.ath !== undefined) return '!ath at the authorization server';
      if (stub.dpopNonce && payload.nonce !== stub.dpopNonce) return '!nonce';
      const jkt = await calculateJwkThumbprint(key, 'sha256');
      stub.proofs.push({
        where, htm: String(payload.htm), htu: String(payload.htu), jkt,
        ...(typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
        ...(typeof payload.ath === 'string' ? { ath: payload.ath } : {}),
      });
      return jkt;
    } catch (err) {
      return `!${(err as Error).message}`;
    }
  }

  function tokenFor(row: Issued, jkt: string | undefined): Record<string, unknown> {
    const accessToken = randomBytes(16).toString('hex');
    const refreshToken = randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      iss: stub.url,
      sub: row.sub,
      aud: stub.aud,
      exp: stub.exp ?? now + 300,
      iat: stub.exp ? stub.exp : stub.futureIat ? now + 120 : now,
      nonce: row.nonce,
      email: row.email,
      name: 'Demo User',
      preferred_username: row.sub,
      sid: row.sid,
      ...(row.acr ? { acr: row.acr } : {}),
      ...(stub.omitAtHash ? {} : { at_hash: stub.badAtHash ? 'aaaa' : atHash(accessToken) }),
    };
    const token = idToken(payload, { corrupt: stub.corrupt, typ: stub.typ, alg: stub.signAlg });
    refresh.set(refreshToken, row);
    access.set(accessToken, { claims: payload, ...(jkt ? { jkt } : {}) });
    stub.aud = CLIENT;
    stub.corrupt = false;
    stub.badAtHash = false;
    stub.exp = undefined;
    return {
      access_token: accessToken,
      token_type: stub.tokenType ?? (jkt ? 'DPoP' : 'Bearer'),
      expires_in: stub.expiresIn,
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
        const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
          res.writeHead(status, { 'content-type': 'application/json', ...headers });
          res.end(JSON.stringify(body));
        };
        const nonceChallenge = (resource: boolean) => {
          stub.challenges += 1;
          if (resource) {
            return json(401, { error: 'use_dpop_nonce' }, {
              'www-authenticate': 'DPoP error="use_dpop_nonce", error_description="a nonce is required"',
              'dpop-nonce': stub.dpopNonce!,
            });
          }
          return json(400, { error: 'use_dpop_nonce', error_description: 'a nonce is required' }, { 'dpop-nonce': stub.dpopNonce! });
        };
        if (url.pathname === '/.well-known/openid-configuration') return json(200, metadata());
        if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
        if (url.pathname === '/userinfo') {
          const authorization = String(req.headers.authorization ?? '');
          const [scheme, token = ''] = authorization.split(' ');
          const row = access.get(token);
          if (!row) return json(401, { error: 'invalid_token' });
          if (row.jkt) {
            if (scheme !== 'DPoP') return json(401, { error: 'invalid_token' }, { 'www-authenticate': 'DPoP error="invalid_token"' });
            const jkt = await proofOf(req, 'userinfo', token);
            if (jkt === '!nonce') return nonceChallenge(true);
            if (jkt !== row.jkt) return json(401, { error: 'invalid_dpop_proof', detail: jkt }, { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' });
          } else if (scheme !== 'Bearer') {
            return json(401, { error: 'invalid_token' });
          }
          return json(200, row.claims);
        }
        if (url.pathname === '/par' && req.method === 'POST') {
          if (!await authorized(req, text)) return json(401, { error: 'invalid_client' });
          const jkt = await proofOf(req, 'par');
          if (jkt === '!nonce') return nonceChallenge(false);
          if (jkt?.startsWith('!')) return json(400, { error: 'invalid_dpop_proof', error_description: jkt });
          const params = new URLSearchParams(text);
          if (jkt && params.get('dpop_jkt') && params.get('dpop_jkt') !== jkt) return json(400, { error: 'invalid_dpop_proof' });
          const requestUri = `urn:par:${randomBytes(8).toString('hex')}`;
          pushed.set(requestUri, params);
          return json(201, { request_uri: requestUri, expires_in: 60 });
        }
        if (url.pathname === '/authorize') {
          const stored = url.searchParams.get('request_uri');
          if (!stored && stub.requirePar) return json(400, { error: 'invalid_request', error_description: 'PAR is required' });
          const params = stored ? pushed.get(stored) : url.searchParams;
          if (!params) return json(400, { error: 'invalid_request' });
          stub.lastAuthorize = new URLSearchParams(params);
          const redirect = params.get('redirect_uri') ?? '';
          const state = params.get('state') ?? '';
          const challenge = params.get('code_challenge') ?? '';
          if (params.get('code_challenge_method') !== 'S256' || !challenge) return json(400, { error: 'invalid_request' });
          const row: Issued = {
            sub: 'user-1', email: 'user-1@example.com', sid: 'sid-1', nonce: params.get('nonce') ?? '',
            ...(stub.acr ? { acr: stub.acr } : {}),
          };
          const code = randomBytes(16).toString('hex');
          const jkt = params.get('dpop_jkt');
          codes.set(code, { ...row, redirect, challenge, ...(jkt ? { jkt } : {}) });
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
          const jkt = await proofOf(req, 'token');
          if (jkt === '!nonce') return nonceChallenge(false);
          if (jkt?.startsWith('!')) return json(400, { error: 'invalid_dpop_proof', error_description: jkt });
          const params = new URLSearchParams(text);
          stub.grants.push(params.get('grant_type') ?? '');
          if (params.get('grant_type') === 'client_credentials') {
            const token = `cc-${randomBytes(8).toString('hex')}`;
            access.set(token, { claims: { sub: CLIENT }, ...(jkt ? { jkt } : {}) });
            return json(200, {
              access_token: token, token_type: stub.tokenType ?? (jkt ? 'DPoP' : 'Bearer'),
              expires_in: 120, scope: params.get('scope'),
            });
          }
          if (params.get('grant_type') === 'refresh_token') {
            if (stub.refreshFails) return json(400, { error: 'invalid_grant' });
            const row = refresh.get(params.get('refresh_token') ?? '');
            if (!row) return json(400, { error: 'invalid_grant' });
            // The refreshed ID token carries the acr the stub is set to now, so a test can show that
            // the refresh path does not check acr again.
            const minted = tokenFor({ ...row, acr: stub.acr ?? '' }, jkt);
            const claims = access.get(String(minted.access_token))!.claims;
            return json(200, { ...minted, id_token: idToken({ ...claims, nonce: undefined }, { typ: stub.typ, alg: stub.signAlg }) });
          }
          const code = params.get('code') ?? '';
          const row = codes.get(code);
          if (!row) return json(400, { error: 'invalid_grant' });
          if (params.get('redirect_uri') !== row.redirect) return json(400, { error: 'invalid_grant' });
          const verifier = params.get('code_verifier') ?? '';
          const got = createHash('sha256').update(verifier).digest('base64url');
          if (got !== row.challenge) return json(400, { error: 'invalid_grant', error_description: 'pkce' });
          if (row.jkt && row.jkt !== jkt) return json(400, { error: 'invalid_grant', error_description: 'dpop_jkt does not match the proof' });
          codes.delete(code);
          return json(200, tokenFor(row, jkt));
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
  stub.close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return stub;
}

/** A configuration built by hand, the way RelyingParty.create() takes one: no defaults filled. */
export function config(stub: Stub, over: Partial<RelyingPartyConfig> = {}): RelyingPartyConfig {
  return {
    metadataUrl: `${stub.url}/.well-known/openid-configuration`,
    clientId: CLIENT,
    clientSecret: SECRET,
    tokenEndpointAuthMethod: 'client_secret_basic',
    redirectUri: `http://127.0.0.1/callback`,
    postLogoutRedirectUri: `http://127.0.0.1/`,
    scopes: SCOPES,
    allowInsecure: true,
    ...over,
  };
}

/** Runs one sign-in: the authorization request, the stub's redirect, and the code exchange. */
export async function signIn(rp: RelyingParty, options: Parameters<RelyingParty['authorize']>[0] = {},
  complete: Parameters<RelyingParty['complete']>[2] = {}) {
  const request = await rp.authorize(options);
  const response = await fetch(request.url, { redirect: 'manual' });
  const location = response.headers.get('location');
  assert.ok(location, `the provider did not redirect (${response.status})`);
  const query = new URL(location).searchParams;
  const login = await rp.complete(query, request, complete);
  return { request, query, login };
}
