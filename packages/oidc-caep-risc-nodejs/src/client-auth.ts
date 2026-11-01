import { randomUUID } from 'node:crypto';
import { SignJWT, importPKCS8, type CryptoKey, type KeyObject } from 'jose';
import type { ResolvedConfig } from './config.ts';
import { OidcError } from './errors.ts';

/** application/x-www-form-urlencoded, which is how a Basic client id and secret are encoded (RFC 6749). */
function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, '+');
}

export type SigningKey = CryptoKey | KeyObject;

/** Loads a PKCS#8 PEM for `private_key_jwt`. A key that does not match `alg` fails here, at startup. */
export async function loadPrivateKey(pem: string, alg: string): Promise<SigningKey> {
  try {
    return await importPKCS8(pem, alg);
  } catch (err) {
    throw new OidcError('config', `the private key could not be read as ${alg}: ${(err as Error).message}`, { cause: err });
  }
}

/**
 * Adds this client's authentication to a token or pushed-authorization request.
 * `aud` is the issuer, as its sole audience: that is what iya-sts requires of a client assertion.
 */
export async function applyClientAuth(config: ResolvedConfig, key: SigningKey | undefined, body: URLSearchParams,
  headers: Record<string, string>, audience: string): Promise<void> {
  if (config.tokenEndpointAuthMethod === 'client_secret_basic') {
    const raw = `${formEncode(config.clientId)}:${formEncode(config.clientSecret ?? '')}`;
    headers.authorization = `Basic ${Buffer.from(raw, 'utf8').toString('base64')}`;
    return;
  }
  if (config.tokenEndpointAuthMethod === 'client_secret_post') {
    body.set('client_id', config.clientId);
    body.set('client_secret', config.clientSecret ?? '');
    return;
  }
  if (!key) throw new OidcError('config', 'private_key_jwt has no signing key');
  const now = Math.floor(Date.now() / 1000);
  let assertion: string;
  try {
    assertion = await new SignJWT({})
      .setProtectedHeader({ alg: config.privateKeyAlg, typ: 'JWT' })
      .setIssuer(config.clientId)
      .setSubject(config.clientId)
      .setAudience(audience)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(key);
  } catch (err) {
    throw new OidcError('protocol', `the client assertion could not be signed: ${(err as Error).message}`, { cause: err });
  }
  body.set('client_id', config.clientId);
  body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  body.set('client_assertion', assertion);
}
