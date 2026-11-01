/**
 * What kind of failure an {@link OidcError} is. An application usually answers every one of them the
 * same way (the sign-in failed, start again), and logs the code and message for the operator.
 *
 * - `config`: the configuration is incomplete or contradictory.
 * - `discovery`: the OpenID Provider metadata could not be fetched or does not describe a code-flow provider.
 * - `protocol`: the provider answered an OAuth error, or not with the document this client asked for.
 * - `validation`: a token or callback verified but a check on its content failed (audience, nonce, hash, time).
 * - `signature`: a token's signature does not verify, or uses an algorithm this client refuses.
 * - `ssf`: the Shared Signals transmitter could not be found, or its stream created or polled.
 */
export type OidcErrorCode = 'config' | 'discovery' | 'protocol' | 'validation' | 'signature' | 'ssf';

/** Every failure this module reports is one of these. */
export class OidcError extends Error {
  /** What kind of failure it is. */
  readonly code: OidcErrorCode;
  /** The OAuth `error` code, when the provider named one (`invalid_client`, `invalid_grant`, ...). */
  readonly oauthError?: string;

  constructor(code: OidcErrorCode, message: string, options: { cause?: unknown; oauthError?: string } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'OidcError';
    this.code = code;
    if (options.oauthError) this.oauthError = options.oauthError;
  }
}
