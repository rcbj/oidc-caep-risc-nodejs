import { createHash, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { ASYMMETRIC_JWS_ALGS } from './discovery.ts';
import { OidcError } from './errors.ts';
import { send, type TlsOptions } from './http.ts';

/** `typ` values that are some other token. An ID token must not carry one (RFC 8725). */
const NOT_ID_TOKEN = new Set([
  'at+jwt', 'application/at+jwt', 'logout+jwt', 'secevent+jwt', 'dpop+jwt',
  'token-introspection+jwt', 'software-statement+jwt', 'jwt-bearer',
]);

export interface IdTokenChecks {
  issuer: string;
  clientId: string;
  /** The only algorithms to accept. HMAC names are verified with `clientSecret` and nothing else. */
  algorithms: string[];
  jwks: JWTVerifyGetKey;
  nonce?: string;
  accessToken?: string;
  code?: string;
  maxAge?: number;
  clockToleranceSec: number;
  maxIdTokenAgeSec: number;
  /** When a refresh returns an ID token, its `sub` must be this one (OIDC Core section 12.2). */
  previousSub?: string;
  clientSecret?: string;
}

function same(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** The hash half an `at_hash` or `c_hash` is: base64url of the left half of the digest the `alg` names. */
export function hashClaim(value: string, alg: string): string {
  const name = alg === 'EdDSA' || alg === 'Ed25519' ? 'sha512'
    : alg.includes('384') ? 'sha384'
      : alg.includes('512') ? 'sha512'
        : 'sha256';
  const digest = createHash(name).update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

function checkHash(claim: unknown, value: string, alg: string, name: string): void {
  if (claim === undefined) return;
  if (typeof claim !== 'string' || !same(claim, hashClaim(value, alg))) {
    throw new OidcError('validation', `the ID token's ${name} does not match`);
  }
}

/**
 * Verifies an ID token: signature, issuer, audience, time, `typ`, `nonce`, `azp`, and `at_hash` / `c_hash`
 * when those claims are present. Returns the payload.
 */
export async function validateIdToken(token: string, checks: IdTokenChecks): Promise<Record<string, unknown>> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(token) as Record<string, unknown>;
  } catch (err) {
    throw new OidcError('signature', `the ID token is not a compact JWS: ${(err as Error).message}`, { cause: err });
  }
  const alg = String(header.alg ?? '');
  if (!checks.algorithms.includes(alg)) throw new OidcError('signature', `the ID token is signed with ${alg || '(no alg)'}, which this client does not accept`);
  if (header.crit !== undefined) throw new OidcError('validation', 'the ID token has a crit header this client does not understand');
  const typ = header.typ === undefined ? '' : String(header.typ).toLowerCase();
  if (typ && (typ !== 'jwt' && typ !== 'application/jwt' || NOT_ID_TOKEN.has(typ))) {
    throw new OidcError('validation', `the ID token typ is ${String(header.typ)}, not an ID token`);
  }
  const hmac = alg.startsWith('HS');
  if (hmac && !checks.clientSecret) throw new OidcError('config', `${alg} ID tokens need the client secret`);
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(token, hmac ? new TextEncoder().encode(checks.clientSecret) : checks.jwks, {
      issuer: checks.issuer,
      audience: checks.clientId,
      algorithms: [alg],
      clockTolerance: checks.clockToleranceSec,
      maxTokenAge: `${checks.maxIdTokenAgeSec}s`,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch (err) {
    if (err instanceof OidcError) throw err;
    const message = (err as Error).message;
    const signature = /signature/i.test(message);
    throw new OidcError(signature ? 'signature' : 'validation', `the ID token was refused: ${message}`, { cause: err });
  }
  if (typeof payload.sub !== 'string' || !payload.sub) throw new OidcError('validation', 'the ID token has no sub');
  const aud = payload.aud;
  const audiences = Array.isArray(aud) ? aud.map(String) : [String(aud ?? '')];
  if (audiences.length > 1 && payload.azp !== checks.clientId) {
    throw new OidcError('validation', 'an ID token with several audiences must name this client as azp');
  }
  if (payload.azp !== undefined && payload.azp !== checks.clientId) {
    throw new OidcError('validation', `the ID token azp is ${String(payload.azp)}, not ${checks.clientId}`);
  }
  if (checks.nonce !== undefined) {
    if (typeof payload.nonce !== 'string' || !same(payload.nonce, checks.nonce)) {
      throw new OidcError('validation', 'the ID token nonce does not match this sign-in');
    }
  }
  if (checks.previousSub !== undefined && payload.sub !== checks.previousSub) {
    throw new OidcError('validation', 'the refreshed ID token is for a different subject');
  }
  if (checks.accessToken) checkHash(payload.at_hash, checks.accessToken, alg, 'at_hash');
  if (checks.code) checkHash(payload.c_hash, checks.code, alg, 'c_hash');
  if (checks.maxAge !== undefined) {
    if (typeof payload.auth_time !== 'number') throw new OidcError('validation', 'max_age was requested and the ID token has no auth_time');
    if (payload.auth_time < Math.floor(Date.now() / 1000) - checks.maxAge - checks.clockToleranceSec) {
      throw new OidcError('validation', 'the ID token auth_time is older than max_age');
    }
  }
  return payload;
}

/** Fetches a JWKS and returns a verifier. Called again when a signature names a key this copy does not hold. */
export async function fetchJwks(jwksUri: string, tls: TlsOptions): Promise<JWTVerifyGetKey> {
  const answer = await send(jwksUri, { headers: { accept: 'application/json' } }, tls, 'discovery');
  if (answer.status !== 200) throw new OidcError('discovery', `the JWKS at ${jwksUri} answered ${answer.status}`);
  let body: unknown;
  try {
    body = JSON.parse(answer.body);
  } catch (err) {
    throw new OidcError('discovery', `the JWKS at ${jwksUri} is not JSON`, { cause: err });
  }
  const keys = (body as { keys?: unknown }).keys;
  if (!body || typeof body !== 'object' || !Array.isArray(keys)) throw new OidcError('discovery', `the JWKS at ${jwksUri} has no keys`);
  return createLocalJWKSet(body as { keys: [] });
}

/** The algorithms an ID token from this provider may use: the configured one, or the asymmetric overlap. */
export function idTokenAlgorithms(advertised: readonly string[], pinned?: string): string[] {
  if (pinned) {
    if (!advertised.includes(pinned)) throw new OidcError('discovery', `the provider does not advertise id_token alg ${pinned}`);
    return [pinned];
  }
  const allowed = advertised.filter((alg) => (ASYMMETRIC_JWS_ALGS as readonly string[]).includes(alg));
  if (!allowed.length) throw new OidcError('discovery', `none of the provider's ID token algorithms can be verified (${advertised.join(', ')})`);
  return allowed;
}
