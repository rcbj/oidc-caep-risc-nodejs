// Verifying a Security Event Token (RFC 8417, a JWT) against the transmitter's published keys, with
// node:crypto. The key is chosen by `kid` from the JWKS, never from the token. `none` and the HMAC
// algorithms are refused: a transmitter signs with its private key.

import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { OidcError } from '../errors.ts';

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  [member: string]: unknown;
}

const ALGS: Record<string, { hash: string | null; kty: string; pss?: boolean; p1363?: boolean }> = {
  RS256: { hash: 'sha256', kty: 'RSA' },
  RS384: { hash: 'sha384', kty: 'RSA' },
  RS512: { hash: 'sha512', kty: 'RSA' },
  PS256: { hash: 'sha256', kty: 'RSA', pss: true },
  PS384: { hash: 'sha384', kty: 'RSA', pss: true },
  PS512: { hash: 'sha512', kty: 'RSA', pss: true },
  ES256: { hash: 'sha256', kty: 'EC', p1363: true },
  ES384: { hash: 'sha384', kty: 'EC', p1363: true },
  ES512: { hash: 'sha512', kty: 'EC', p1363: true },
  EdDSA: { hash: null, kty: 'OKP' },
  Ed25519: { hash: null, kty: 'OKP' },
};

/** The JWS algorithms this module verifies. */
export const SUPPORTED_JWS_ALGS = Object.keys(ALGS);

const b64url = (value: string, what: string): Buffer => {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new OidcError('signature', `the SET's ${what} is not base64url`);
  return Buffer.from(value, 'base64url');
};

function keyFor(jwk: Jwk): KeyObject {
  try {
    return createPublicKey({ key: jwk as never, format: 'jwk' });
  } catch (err) {
    throw new OidcError('signature', `the transmitter's key ${jwk.kid ?? ''} cannot be read: ${(err as Error).message}`, { cause: err });
  }
}

export interface VerifiedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

/** Verifies a compact JWS against the keys of a JWKS and returns its header and payload. */
export function verifyCompactJws(token: string, keys: readonly Jwk[]): VerifiedJws {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) throw new OidcError('signature', 'the SET is not a compact JWS');
  const h = parts[0];
  const p = parts[1];
  const s = parts[2];
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(b64url(h, 'header').toString('utf8'));
    payload = JSON.parse(b64url(p, 'payload').toString('utf8'));
  } catch (err) {
    if (err instanceof OidcError) throw err;
    throw new OidcError('signature', 'the SET\'s header or payload is not JSON', { cause: err });
  }
  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') {
    throw new OidcError('signature', 'the SET\'s header or payload is not a JSON object');
  }
  const alg = String(header.alg ?? '');
  const spec = ALGS[alg];
  if (!spec) throw new OidcError('signature', `the SET is signed with ${alg || '(no alg)'}, which this receiver does not verify (${SUPPORTED_JWS_ALGS.join(', ')})`);
  if (header.crit !== undefined) throw new OidcError('signature', 'the SET\'s header has a crit member this receiver does not understand');
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const candidates = keys.filter((k) => (kid ? k.kid === kid : true) && k.kty === spec.kty && (!k.use || k.use === 'sig') && (!k.alg || k.alg === alg));
  if (!candidates.length) throw new OidcError('signature', `the transmitter publishes no ${spec.kty} signing key${kid ? ` with kid ${kid}` : ''}`);
  const data = Buffer.from(`${h}.${p}`, 'ascii');
  const sig = b64url(s, 'signature');
  for (const jwk of candidates) {
    const key = keyFor(jwk);
    const ok = spec.hash === null
      ? verify(null, data, key, sig)
      : verify(spec.hash, data, spec.pss
        ? { key, padding: 6, saltLength: -1 }
        : spec.p1363 ? { key, dsaEncoding: 'ieee-p1363' } : key, sig);
    if (ok) return { header, payload };
  }
  throw new OidcError('signature', 'the SET\'s signature does not verify against the transmitter\'s keys');
}
