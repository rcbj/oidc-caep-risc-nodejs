import { OidcError } from './errors.ts';
import { send, type TlsOptions } from './http.ts';

/** Asymmetric JWS algorithms this client verifies. HMAC algorithms are accepted only when named explicitly. */
export const ASYMMETRIC_JWS_ALGS = Object.freeze([
  'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519',
]);

/**
 * The scopes the demo and {@link RelyingParty} ask for unless the configuration names others.
 * The same set the browser client in oidc-caep-client registers: OpenID identity, a refresh token,
 * and the Shared Signals read and manage scopes.
 */
export const DEFAULT_SCOPES = 'openid profile email offline_access ssf.read ssf.manage';

const REQUIRED = [
  'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
  'response_types_supported', 'subject_types_supported', 'id_token_signing_alg_values_supported',
] as const;

/** OpenID Provider metadata this client uses. Other members are kept and ignored. */
export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  revocation_endpoint?: string;
  response_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
  grant_types_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
}

/** The issuer a discovery URL was built from: the URL with `/.well-known/openid-configuration` removed. */
export function issuerFromMetadataUrl(metadataUrl: string): string {
  let url: URL;
  try {
    url = new URL(metadataUrl);
  } catch {
    throw new OidcError('config', `metadataUrl is not a URL: ${metadataUrl}`);
  }
  const marker = '/.well-known/openid-configuration';
  const at = url.pathname.indexOf(marker);
  if (at < 0) throw new OidcError('config', `metadataUrl must be the openid-configuration URL, not ${metadataUrl}`);
  const path = url.pathname.slice(0, at).replace(/\/+$/, '');
  return `${url.origin}${path}`;
}

function mustBeUrl(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value) throw new OidcError('discovery', `OpenID Provider metadata ${name} is missing`);
  try {
    const url = new URL(value);
    if (name === 'issuer' && (url.search || url.hash)) throw new OidcError('discovery', 'issuer must not contain a query or fragment');
    return value;
  } catch (err) {
    if (err instanceof OidcError) throw err;
    throw new OidcError('discovery', `OpenID Provider metadata ${name} is not a valid URL`);
  }
}

/**
 * Checks an OpenID Provider metadata document for a confidential Authorization Code client.
 * `expectedIssuer`, when given, must equal `issuer` exactly (Discovery 1.0 section 4.3).
 */
export function validateProviderMetadata(raw: unknown, expectedIssuer?: string): ProviderMetadata {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new OidcError('discovery', 'OpenID Provider metadata must be a JSON object');
  }
  const doc = raw as Record<string, unknown>;
  const missing = REQUIRED.filter((key) => doc[key] === undefined);
  if (missing.length) throw new OidcError('discovery', `OpenID Provider metadata is missing ${missing.join(', ')}`);
  const metadata = {
    issuer: mustBeUrl(doc.issuer, 'issuer'),
    authorization_endpoint: mustBeUrl(doc.authorization_endpoint, 'authorization_endpoint'),
    token_endpoint: mustBeUrl(doc.token_endpoint, 'token_endpoint'),
    jwks_uri: mustBeUrl(doc.jwks_uri, 'jwks_uri'),
    response_types_supported: doc.response_types_supported,
    subject_types_supported: doc.subject_types_supported,
    id_token_signing_alg_values_supported: doc.id_token_signing_alg_values_supported,
  } as ProviderMetadata;
  for (const key of ['userinfo_endpoint', 'end_session_endpoint', 'pushed_authorization_request_endpoint', 'revocation_endpoint'] as const) {
    if (doc[key] !== undefined) metadata[key] = mustBeUrl(doc[key], key);
  }
  for (const key of ['token_endpoint_auth_methods_supported', 'code_challenge_methods_supported', 'scopes_supported', 'grant_types_supported'] as const) {
    if (doc[key] !== undefined) {
      if (!Array.isArray(doc[key])) throw new OidcError('discovery', `${key} must be an array`);
      metadata[key] = (doc[key] as unknown[]).map(String);
    }
  }
  if (doc.authorization_response_iss_parameter_supported !== undefined) {
    metadata.authorization_response_iss_parameter_supported = doc.authorization_response_iss_parameter_supported === true;
  }
  if (!Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.map(String).includes('code')) {
    throw new OidcError('discovery', 'OpenID Provider does not support response_type=code');
  }
  metadata.response_types_supported = metadata.response_types_supported.map(String);
  if (!Array.isArray(metadata.subject_types_supported)) throw new OidcError('discovery', 'subject_types_supported must be an array');
  metadata.subject_types_supported = metadata.subject_types_supported.map(String);
  if (!Array.isArray(metadata.id_token_signing_alg_values_supported)) {
    throw new OidcError('discovery', 'id_token_signing_alg_values_supported must be an array');
  }
  metadata.id_token_signing_alg_values_supported = metadata.id_token_signing_alg_values_supported.map(String);
  if (expectedIssuer !== undefined && metadata.issuer !== expectedIssuer) {
    throw new OidcError('discovery', `issuer mismatch: expected "${expectedIssuer}", got "${metadata.issuer}"`);
  }
  return metadata;
}

/** Fetches and checks `metadataUrl`. Its issuer must be the issuer the URL was built from. */
export async function discoverProvider(metadataUrl: string, tls: TlsOptions = {}): Promise<ProviderMetadata> {
  const expected = issuerFromMetadataUrl(metadataUrl);
  const answer = await send(metadataUrl, { headers: { accept: 'application/json' } }, tls, 'discovery');
  if (answer.status !== 200) throw new OidcError('discovery', `${metadataUrl} answered ${answer.status}`);
  let body: unknown;
  try {
    body = JSON.parse(answer.body);
  } catch (err) {
    throw new OidcError('discovery', `${metadataUrl} did not answer JSON`, { cause: err });
  }
  return validateProviderMetadata(body, expected);
}

/** RFC 8414 well-known URLs for a suffix such as `ssf-configuration`: path insertion, then the appended form. */
export function wellKnownUrls(issuer: string, suffix: string): string[] {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/+$/, '');
  const inserted = `${url.origin}/.well-known/${suffix}${path}`;
  const appended = `${url.origin}${path}/.well-known/${suffix}`;
  return inserted === appended ? [inserted] : [inserted, appended];
}
