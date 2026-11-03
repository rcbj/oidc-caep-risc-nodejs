import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { DEFAULT_SCOPES, issuerFromMetadataUrl, trimTrailingSlashes, validateProviderMetadata, type ProviderMetadata } from './discovery.ts';
import { OidcError } from './errors.ts';

/** How this client authenticates to the token endpoint. `none` is a public client, and this library refuses it. */
export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';

const AUTH_METHODS: readonly TokenEndpointAuthMethod[] = ['client_secret_basic', 'client_secret_post', 'private_key_jwt'];

/** A configuration file, or the object {@link resolveConfig} accepts. Names follow oidc-caep-client where they overlap. */
export interface OidcConfigFile {
  /** Issuer. With `metadataUrl`, it must be the issuer that URL was built from. */
  issuer?: string;
  /** `https://idp.example/.well-known/openid-configuration`, the name oidc-caep-client uses. */
  metadataUrl?: string;
  /** A metadata document on disk, used instead of fetching `metadataUrl`. */
  metadataFile?: string;
  clientId?: string;
  /** oidc-caep-client's name for the same field. */
  client_id?: string;
  /**
   * The client secret, a `file:` path next to the configuration, or `env:VARIABLE`.
   * Required for `client_secret_basic` and `client_secret_post`.
   */
  clientSecret?: string;
  /** PEM PKCS#8 private key, a path, `file:` or `env:`. Required for `private_key_jwt`. */
  privateKey?: string;
  /** Algorithm the private key signs the client assertion with. Default `RS256`. */
  privateKeyAlg?: string;
  tokenEndpointAuthMethod?: string;
  redirectUri?: string;
  redirect_uri?: string;
  postLogoutRedirectUri?: string;
  post_logout_redirect_uri?: string;
  /** A space-separated string, as in oidc-caep-client's `oidc.json`, or an array. */
  scopes?: string | string[];
  /** The one ID token `alg` to accept. When set, it replaces `idTokenSigningAlgs`. It must be advertised. */
  idTokenSignedResponseAlg?: string;
  /**
   * The ID token algorithms to accept. Default `["RS256"]`. Each must also be advertised by the
   * provider; `none` is refused. An HMAC algorithm is accepted only when it is named here (or pinned).
   */
  idTokenSigningAlgs?: string[];
  /**
   * Default true: the ID token header must carry `typ` (`JWT` or `application/jwt`), and when the token
   * response carries an access token, the ID token must carry a matching `at_hash`. false checks each
   * only when it is present, for a provider that omits them.
   */
  requireIdTokenTypAndAtHash?: boolean;
  /**
   * Pushed Authorization Requests. Default `auto`: used when the provider advertises them, and always
   * when it sets `require_pushed_authorization_requests` (then `never` fails at creation).
   */
  par?: 'auto' | 'always' | 'never';
  /**
   * DPoP (RFC 9449). Default `auto`: used when the provider advertises ES256 in
   * `dpop_signing_alg_values_supported`. `always` fails at creation when it does not. `never` sends no proofs.
   */
  dpop?: 'auto' | 'always' | 'never';
  /**
   * The DPoP private key: a P-256 PEM, a path, `file:` or `env:`. Default: a key generated when the
   * relying party is created, held in memory only. Name one when several processes share sign-ins.
   */
  dpopKey?: string;
  /** `acr_values` for every authorization request: a space-separated string or an array. The ID token's `acr` must be one of them. */
  acrValues?: string | string[];
  /** Seconds of clock skew allowed on `exp`, `iat` and `auth_time`. Default 30. */
  clockToleranceSec?: number;
  /** The oldest ID token `iat` accepted, in seconds. Default 600. */
  maxIdTokenAgeSec?: number;
  /** Allow an `http` issuer and endpoints. Redirect URIs are https, or http on a loopback host, either way. Default false. */
  allowInsecure?: boolean;
  /**
   * CA trust chain for the provider's TLS listener certificate, in addition to node's own store.
   * PEM, `file:path`, `env:NAME`, or a path. A missing file is ignored.
   * iya-sts publishes this bundle at `GET /tls/server-certificate` (leaf, intermediates, and the root).
   */
  tlsCa?: string;
  /**
   * CAEP and RISC. Omitted or true keeps them on. false does not resolve `ssf`, does not contact a
   * transmitter, and drops `ssf.read` and `ssf.manage` from the scopes.
   */
  signals?: boolean;
  ssf?: { transmitter?: string; pollIntervalMs?: number };
}

/** Configuration after paths and secrets have been read. */
export interface ResolvedConfig {
  issuer?: string;
  metadataUrl?: string;
  metadata?: ProviderMetadata;
  clientId: string;
  clientSecret?: string;
  privateKeyPem?: string;
  privateKeyAlg: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUri: string;
  postLogoutRedirectUri?: string;
  scopes: string;
  idTokenSignedResponseAlg?: string;
  idTokenSigningAlgs: string[];
  requireIdTokenTypAndAtHash: boolean;
  par: 'auto' | 'always' | 'never';
  dpop: 'auto' | 'always' | 'never';
  /** PEM P-256 private key for DPoP. Absent: one is generated when the relying party is created. */
  dpopKeyPem?: string;
  /** Space-separated `acr_values` sent on every authorization request. */
  acrValues?: string;
  clockToleranceSec: number;
  maxIdTokenAgeSec: number;
  allowInsecure: boolean;
  tlsCa?: string;
  /** Set only when CAEP and RISC are off. Omitted means on. */
  signals?: false;
  ssf?: { transmitter: string; pollIntervalMs?: number };
}

/** The members of {@link ResolvedConfig} that have a default. */
type Defaulted = 'privateKeyAlg' | 'idTokenSigningAlgs' | 'requireIdTokenTypAndAtHash' | 'par' | 'dpop'
  | 'clockToleranceSec' | 'maxIdTokenAgeSec' | 'allowInsecure';

/**
 * What {@link RelyingParty.create} accepts: a {@link ResolvedConfig} whose defaulted members may be
 * left out. They are filled, and every member is checked, exactly as when the configuration is read
 * from a file.
 */
export type RelyingPartyConfig = Omit<ResolvedConfig, Defaulted> & Partial<Pick<ResolvedConfig, Defaulted>>;

/** The ID token algorithms accepted when the configuration names none. */
export const DEFAULT_ID_TOKEN_SIGNING_ALGS: readonly string[] = Object.freeze(['RS256']);

function asObject(raw: unknown): OidcConfigFile {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new OidcError('config', 'the configuration must be a JSON object');
  return raw as OidcConfigFile;
}

function readPath(path: string, baseDir: string, what: string): string {
  const full = isAbsolute(path) ? path : resolve(baseDir, path);
  try {
    return readFileSync(full, 'utf8').trim();
  } catch (err) {
    throw new OidcError('config', `could not read ${what} at ${full}: ${(err as Error).message}`, { cause: err });
  }
}

/** `env:NAME`, `file:path`, or the value itself. */
function secretValue(raw: string, baseDir: string, what: string): string {
  if (raw.startsWith('env:')) {
    const name = raw.slice(4);
    const value = process.env[name];
    if (!value) throw new OidcError('config', `${what} reads ${name}, and that variable is empty`);
    return value;
  }
  if (raw.startsWith('file:')) return readPath(raw.slice(5), baseDir, what);
  return raw;
}

/** A PEM, `env:`, `file:`, or a filesystem path. */
function keyValue(raw: string, baseDir: string, what: string): string {
  if (raw.startsWith('env:') || raw.startsWith('file:') || raw.includes('-----BEGIN')) return secretValue(raw, baseDir, what);
  return readPath(raw, baseDir, what);
}

/**
 * The listener CA trust chain: PEM, `file:`, `env:`, or a path.
 * A path that is not there yet is absent, not an error, so a process can start before setup writes it.
 */
function readTrust(raw: string | undefined, baseDir: string): string | undefined {
  if (!raw) return undefined;
  const value = raw.trim();
  if (!value) return undefined;
  if (value.includes('-----BEGIN')) return value;
  if (value.startsWith('env:')) return process.env[value.slice(4)] || undefined;
  const path = value.startsWith('file:') ? value.slice(5) : value;
  const full = isAbsolute(path) ? path : resolve(baseDir, path);
  try {
    return readFileSync(full, 'utf8');
  } catch {
    return undefined;
  }
}

/** Omitted and true keep CAEP and RISC on. Any other value is a configuration error. */
function signalsOn(value: unknown): boolean {
  if (value === undefined || value === true) return true;
  if (value === false) return false;
  throw new OidcError('config', 'signals must be true or false');
}

function isLoopback(url: URL): boolean {
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
}

/**
 * The redirect-URI rule: https, or http on a loopback host (`localhost`, `127.0.0.1`, `[::1]`).
 * It holds for the configured URIs and for a per-request override; `allowInsecure` does not relax it.
 */
export function checkRedirectUri(value: string, name = 'redirectUri'): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OidcError('config', `${name} is not a URL: ${value}`);
  }
  if (url.protocol === 'https:') return value;
  if (url.protocol === 'http:' && isLoopback(url)) return value;
  throw new OidcError('config', `${name} must use https, or http on a loopback host: ${value}`);
}

function mode(value: unknown, name: string): 'auto' | 'always' | 'never' {
  const chosen = value ?? 'auto';
  if (chosen !== 'auto' && chosen !== 'always' && chosen !== 'never') throw new OidcError('config', `${name} must be auto, always, or never`);
  return chosen;
}

function seconds(value: unknown, name: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new OidcError('config', `${name} must be a number of seconds, 0 or more`);
  return value;
}

function algorithms(value: unknown): string[] {
  if (value === undefined) return [...DEFAULT_ID_TOKEN_SIGNING_ALGS];
  if (!Array.isArray(value) || !value.length || value.some((alg) => typeof alg !== 'string' || !alg.trim())) {
    throw new OidcError('config', 'idTokenSigningAlgs must be a non-empty list of algorithm names');
  }
  const list = [...new Set(value.map((alg: string) => alg.trim()))];
  if (list.some((alg) => alg.toLowerCase() === 'none')) throw new OidcError('config', 'idTokenSigningAlgs must not name none');
  return list;
}

function acrList(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const list = Array.isArray(value) ? value.map((v) => String(v).trim()) : String(value).trim().split(/\s+/);
  const joined = list.filter(Boolean).join(' ');
  return joined || undefined;
}

/**
 * Fills the defaults and checks a configuration, however it was made: read from a file by
 * {@link resolveConfig}, or built by hand and passed to {@link RelyingParty.create}.
 */
export function finishConfig(config: RelyingPartyConfig): ResolvedConfig {
  if (!config || typeof config !== 'object') throw new OidcError('config', 'the configuration must be an object');
  if (!config.redirectUri) throw new OidcError('config', 'redirectUri is required');
  if (config.idTokenSignedResponseAlg !== undefined && (!config.idTokenSignedResponseAlg || config.idTokenSignedResponseAlg.toLowerCase() === 'none')) {
    throw new OidcError('config', 'idTokenSignedResponseAlg must name a signing algorithm, not none');
  }
  const require = config.requireIdTokenTypAndAtHash ?? true;
  if (typeof require !== 'boolean') throw new OidcError('config', 'requireIdTokenTypAndAtHash must be true or false');
  const acrValues = acrList(config.acrValues);
  const { acrValues: _acr, ...rest } = config;
  return {
    ...rest,
    privateKeyAlg: config.privateKeyAlg ?? 'RS256',
    redirectUri: checkRedirectUri(config.redirectUri, 'redirectUri'),
    ...(config.postLogoutRedirectUri ? { postLogoutRedirectUri: checkRedirectUri(config.postLogoutRedirectUri, 'postLogoutRedirectUri') } : {}),
    idTokenSigningAlgs: algorithms(config.idTokenSigningAlgs),
    requireIdTokenTypAndAtHash: require,
    par: mode(config.par, 'par'),
    dpop: mode(config.dpop, 'dpop'),
    ...(acrValues ? { acrValues } : {}),
    clockToleranceSec: seconds(config.clockToleranceSec, 'clockToleranceSec', 30),
    maxIdTokenAgeSec: seconds(config.maxIdTokenAgeSec, 'maxIdTokenAgeSec', 600),
    allowInsecure: config.allowInsecure === true,
  };
}

/**
 * Reads a configuration object: resolves `file:` and `env:` secrets, loads metadata and the listener
 * CA trust chain when that file exists, and fills the defaults. `baseDir` is where relative paths start.
 */
export function resolveConfig(raw: unknown, baseDir: string): ResolvedConfig {
  const doc = asObject(raw);
  const clientId = String(doc.clientId ?? doc.client_id ?? '').trim();
  if (!clientId) throw new OidcError('config', 'client_id is required');
  const methodRaw = String(doc.tokenEndpointAuthMethod ?? 'client_secret_basic');
  if (methodRaw === 'none') throw new OidcError('config', 'tokenEndpointAuthMethod "none" is a public client; this library authenticates a confidential client');
  if (!AUTH_METHODS.includes(methodRaw as TokenEndpointAuthMethod)) {
    throw new OidcError('config', `tokenEndpointAuthMethod must be ${AUTH_METHODS.join(', ')}, not ${methodRaw}`);
  }
  const tokenEndpointAuthMethod = methodRaw as TokenEndpointAuthMethod;
  const redirectUri = String(doc.redirectUri ?? doc.redirect_uri ?? '').trim();
  if (!redirectUri) throw new OidcError('config', 'redirectUri is required');
  const allowInsecure = doc.allowInsecure === true;
  const signals = signalsOn(doc.signals);
  let scopes = Array.isArray(doc.scopes)
    ? doc.scopes.map((s) => String(s).trim()).filter(Boolean).join(' ')
    : String(doc.scopes ?? DEFAULT_SCOPES).trim();
  // Drop the Shared Signals scopes after the default is applied. DEFAULT_SCOPES itself stays as it is.
  if (!signals) scopes = scopes.split(/\s+/).filter((scope) => scope !== 'ssf.read' && scope !== 'ssf.manage').join(' ');
  if (!scopes.split(/\s+/).includes('openid')) throw new OidcError('config', 'scopes must include openid');

  let issuer = doc.issuer?.trim() || undefined;
  const metadataUrl = doc.metadataUrl?.trim() || undefined;
  if (metadataUrl) {
    const fromUrl = issuerFromMetadataUrl(metadataUrl);
    if (issuer && issuer !== fromUrl) throw new OidcError('config', `issuer ${issuer} is not the issuer of ${metadataUrl} (${fromUrl})`);
    issuer = fromUrl;
  }
  let metadata: ProviderMetadata | undefined;
  if (doc.metadataFile) {
    const full = isAbsolute(doc.metadataFile) ? doc.metadataFile : resolve(baseDir, doc.metadataFile);
    let body: unknown;
    try {
      body = JSON.parse(readFileSync(full, 'utf8'));
    } catch (err) {
      throw new OidcError('config', `could not read metadata at ${full}: ${(err as Error).message}`, { cause: err });
    }
    metadata = validateProviderMetadata(body, issuer);
    issuer = metadata.issuer;
  }
  if (!metadataUrl && !metadata) throw new OidcError('config', 'metadataUrl or metadataFile is required');

  const needsSecret = tokenEndpointAuthMethod !== 'private_key_jwt';
  let clientSecret: string | undefined;
  if (doc.clientSecret) clientSecret = secretValue(doc.clientSecret, baseDir, 'the client secret');
  if (needsSecret && !clientSecret) throw new OidcError('config', `${tokenEndpointAuthMethod} needs clientSecret`);
  let privateKeyPem: string | undefined;
  if (doc.privateKey) privateKeyPem = keyValue(doc.privateKey, baseDir, 'the private key');
  if (tokenEndpointAuthMethod === 'private_key_jwt' && !privateKeyPem) {
    throw new OidcError('config', 'private_key_jwt needs privateKey');
  }

  const tlsCa = readTrust(doc.tlsCa, baseDir);
  let dpopKeyPem: string | undefined;
  if (doc.dpopKey) dpopKeyPem = keyValue(doc.dpopKey, baseDir, 'the DPoP key');

  const postLogout = String(doc.postLogoutRedirectUri ?? doc.post_logout_redirect_uri ?? '').trim();
  let ssf: ResolvedConfig['ssf'];
  if (signals && doc.ssf?.transmitter) {
    const transmitter = trimTrailingSlashes(doc.ssf.transmitter);
    if (!/^https?:\/\//.test(transmitter)) throw new OidcError('config', 'ssf.transmitter must be an http(s) URL');
    ssf = { transmitter, ...(doc.ssf.pollIntervalMs ? { pollIntervalMs: doc.ssf.pollIntervalMs } : {}) };
  }

  const acrValues = acrList(doc.acrValues);
  return finishConfig({
    ...(issuer ? { issuer } : {}),
    ...(metadataUrl ? { metadataUrl } : {}),
    ...(metadata ? { metadata } : {}),
    clientId,
    ...(clientSecret ? { clientSecret } : {}),
    ...(privateKeyPem ? { privateKeyPem } : {}),
    ...(doc.privateKeyAlg ? { privateKeyAlg: doc.privateKeyAlg } : {}),
    tokenEndpointAuthMethod,
    redirectUri,
    ...(postLogout ? { postLogoutRedirectUri: postLogout } : {}),
    scopes,
    ...(doc.idTokenSignedResponseAlg !== undefined ? { idTokenSignedResponseAlg: doc.idTokenSignedResponseAlg } : {}),
    ...(doc.idTokenSigningAlgs !== undefined ? { idTokenSigningAlgs: doc.idTokenSigningAlgs } : {}),
    ...(doc.requireIdTokenTypAndAtHash !== undefined ? { requireIdTokenTypAndAtHash: doc.requireIdTokenTypAndAtHash } : {}),
    ...(doc.par !== undefined ? { par: doc.par } : {}),
    ...(doc.dpop !== undefined ? { dpop: doc.dpop } : {}),
    ...(dpopKeyPem ? { dpopKeyPem } : {}),
    ...(acrValues ? { acrValues } : {}),
    ...(doc.clockToleranceSec !== undefined ? { clockToleranceSec: doc.clockToleranceSec } : {}),
    ...(doc.maxIdTokenAgeSec !== undefined ? { maxIdTokenAgeSec: doc.maxIdTokenAgeSec } : {}),
    allowInsecure,
    ...(tlsCa ? { tlsCa } : {}),
    ...(signals ? {} : { signals: false as const }),
    ...(ssf ? { ssf } : {}),
  });
}

/** Reads a configuration file and resolves it. Relative paths start in the file's directory. */
export function readConfigFile(path: string): ResolvedConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new OidcError('config', `could not read ${path}: ${(err as Error).message}`, { cause: err });
  }
  return resolveConfig(raw, resolve(path, '..'));
}
