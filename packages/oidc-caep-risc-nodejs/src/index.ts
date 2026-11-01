/**
 * oidc-caep-risc-nodejs: a server-side OpenID Connect confidential client.
 *
 * ```ts
 * import { RelyingParty } from 'oidc-caep-risc-nodejs';
 *
 * const rp = await RelyingParty.fromFile('oidc.json');
 * const request = await rp.authorize();          // keep request.state, nonce and codeVerifier
 * const who = await rp.complete(query, request); // at the redirect URI
 * ```
 *
 * @packageDocumentation
 */

export { RelyingParty } from './relying-party.ts';
export type { AuthorizeOptions, AuthorizeRequest, ClientCredentials, OidcLogin, RefreshOptions, Transaction } from './relying-party.ts';
export { readConfigFile, resolveConfig } from './config.ts';
export type { OidcConfigFile, ResolvedConfig, TokenEndpointAuthMethod } from './config.ts';
export { ASYMMETRIC_JWS_ALGS, DEFAULT_SCOPES, discoverProvider, issuerFromMetadataUrl, validateProviderMetadata, wellKnownUrls } from './discovery.ts';
export type { ProviderMetadata } from './discovery.ts';
export { validateIdToken, hashClaim } from './id-token.ts';
export { codeChallengeS256, randomToken } from './pkce.ts';
export { OidcError } from './errors.ts';
export type { OidcErrorCode } from './errors.ts';
export { SignalsReceiver } from './ssf/receiver.ts';
export type { SignalEvent, SignalsReceiverOptions } from './ssf/receiver.ts';
export { MemorySessionIndex, trackedFromLogin } from './ssf/session-index.ts';
export type { SessionIndex, TrackedSession } from './ssf/session-index.ts';
export { EVENT, CAEP_EVENTS, RISC_EVENTS, DEFAULT_EVENTS_REQUESTED, DEFAULT_ENDING_EVENTS, subjectOf } from './ssf/events.ts';
export type { SubjectRef } from './ssf/events.ts';
