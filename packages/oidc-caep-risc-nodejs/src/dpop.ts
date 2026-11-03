// DPoP (RFC 9449): a key this relying party holds, the proofs it signs with it, and the nonces the
// servers it talks to hand out. One ES256 (P-256) key per relying party. Generated when the relying
// party is created and held in memory only, unless the configuration names a PEM private key
// (`dpopKey`) so that several processes present the same key.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, type JWK } from 'jose';
import { OidcError } from './errors.ts';
import { header, type HttpAnswer } from './http.ts';

/** The one algorithm this library signs proofs with. */
export const DPOP_ALG = 'ES256';

/** `htu`: the request URI without its query and fragment (RFC 9449 section 4.2). */
export function htuOf(url: string): string {
  const target = new URL(url);
  return `${target.origin}${target.pathname}`;
}

/** `ath`: base64url of the SHA-256 of the access token (RFC 9449 section 4.2). */
export function athOf(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

/** Whether a resource server's 401 asks for a DPoP nonce (RFC 9449 section 9). */
export function asksForNonce(answer: HttpAnswer): boolean {
  if (answer.status !== 401) return false;
  const challenge = header(answer, 'www-authenticate') ?? '';
  return /(^|,)\s*DPoP\b/i.test(challenge) && /error\s*=\s*"?use_dpop_nonce"?/i.test(challenge);
}

/** A DPoP key, its public JWK and thumbprint, and the latest nonce each server origin gave. */
export class DpopSigner {
  readonly #key: KeyObject;
  /** The public key, as it goes in a proof's `jwk` header. */
  readonly jwk: JWK;
  /** The JWK SHA-256 thumbprint (RFC 7638): the `dpop_jkt` of an authorization request. */
  readonly thumbprint: string;
  readonly #nonces = new Map<string, string>();

  private constructor(key: KeyObject, jwk: JWK, thumbprint: string) {
    this.#key = key;
    this.jwk = jwk;
    this.thumbprint = thumbprint;
  }

  /** A new P-256 key, or the PEM private key `pem` names. Any other kind of key is refused. */
  static async create(pem?: string): Promise<DpopSigner> {
    let key: KeyObject;
    if (pem) {
      try {
        key = createPrivateKey(pem);
      } catch (err) {
        throw new OidcError('config', `dpopKey could not be read: ${(err as Error).message}`, { cause: err });
      }
      if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
        throw new OidcError('config', 'dpopKey must be a P-256 (ES256) private key');
      }
    } else {
      key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    }
    const exported = createPublicKey(key).export({ format: 'jwk' }) as JWK;
    const jwk: JWK = { kty: exported.kty!, crv: exported.crv!, x: exported.x!, y: exported.y! };
    return new DpopSigner(key, jwk, await calculateJwkThumbprint(jwk, 'sha256'));
  }

  /** The nonce the server at `url`'s origin last gave, if any. */
  nonceFor(url: string): string | undefined {
    return this.#nonces.get(new URL(url).origin);
  }

  /** Keeps the `DPoP-Nonce` a response carried, as the latest for that server's origin. */
  remember(url: string, answer: HttpAnswer): void {
    const nonce = header(answer, 'dpop-nonce');
    if (nonce) this.#nonces.set(new URL(url).origin, nonce);
  }

  /**
   * One proof for one request. `accessToken`, for a resource request, adds `ath`. The latest nonce
   * for the server's origin goes in when there is one.
   */
  async proof(method: string, url: string, accessToken?: string): Promise<string> {
    const nonce = this.nonceFor(url);
    const claims: Record<string, unknown> = {
      jti: randomUUID(),
      htm: method.toUpperCase(),
      htu: htuOf(url),
      ...(nonce ? { nonce } : {}),
      ...(accessToken ? { ath: athOf(accessToken) } : {}),
    };
    try {
      return await new SignJWT(claims)
        .setProtectedHeader({ alg: DPOP_ALG, typ: 'dpop+jwt', jwk: this.jwk })
        .setIssuedAt()
        .sign(this.#key);
    } catch (err) {
      throw new OidcError('protocol', `the DPoP proof could not be signed: ${(err as Error).message}`, { cause: err });
    }
  }
}
