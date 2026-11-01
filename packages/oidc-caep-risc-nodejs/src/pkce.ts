import { createHash, randomBytes } from 'node:crypto';

/** 32 random bytes, base64url. A PKCE verifier (RFC 7636) and a state or nonce. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** RFC 7636 S256: base64url(SHA-256(verifier)), with no padding. */
export function codeChallengeS256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}
