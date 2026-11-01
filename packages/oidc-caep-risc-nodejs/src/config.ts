import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { DEFAULT_SCOPES, issuerFromMetadataUrl, validateProviderMetadata, type ProviderMetadata } from './discovery.ts';
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
  /** The only ID token `alg` to accept. Default: every asymmetric algorithm the provider advertises. */
  idTokenSignedResponseAlg?: string;
  /** Pushed Authorization Requests. Default `auto`: used when the provider advertises them. */
  par?: 'auto' | 'always' | 'never';
  clockToleranceSec?: number;
  maxIdTokenAgeSec?: number;
  /** Allow an `http` issuer. Loopback `http` redirect URIs are allowed either way. Default false. */
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
  par: 'auto' | 'always' | 'never';
  clockToleranceSec: number;
  maxIdTokenAgeSec: number;
  allowInsecure: boolean;
  tlsCa?: string;
  /** Set only when CAEP and RISC are off. Omitted means on. */
  signals?: false;
  ssf?: { transmitter: string; pollIntervalMs?: number };
}

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

function checkRedirect(value: string, name: string, allowInsecure: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OidcError('config', `${name} is not a URL: ${value}`);
  }
  if (url.protocol === 'https:') return value;
  if (url.protocol === 'http:' && (isLoopback(url) || allowInsecure)) return value;
  throw new OidcError('config', `${name} must use https, or http on loopback: ${value}`);
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
  const par = doc.par ?? 'auto';
  if (par !== 'auto' && par !== 'always' && par !== 'never') throw new OidcError('config', 'par must be auto, always, or never');

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

  const postLogout = String(doc.postLogoutRedirectUri ?? doc.post_logout_redirect_uri ?? '').trim();
  let ssf: ResolvedConfig['ssf'];
  if (signals && doc.ssf?.transmitter) {
    const transmitter = doc.ssf.transmitter.replace(/\/+$/, '');
    if (!/^https?:\/\//.test(transmitter)) throw new OidcError('config', 'ssf.transmitter must be an http(s) URL');
    ssf = { transmitter, ...(doc.ssf.pollIntervalMs ? { pollIntervalMs: doc.ssf.pollIntervalMs } : {}) };
  }

  return {
    ...(issuer ? { issuer } : {}),
    ...(metadataUrl ? { metadataUrl } : {}),
    ...(metadata ? { metadata } : {}),
    clientId,
    ...(clientSecret ? { clientSecret } : {}),
    ...(privateKeyPem ? { privateKeyPem } : {}),
    privateKeyAlg: doc.privateKeyAlg ?? 'RS256',
    tokenEndpointAuthMethod,
    redirectUri: checkRedirect(redirectUri, 'redirectUri', allowInsecure),
    ...(postLogout ? { postLogoutRedirectUri: checkRedirect(postLogout, 'postLogoutRedirectUri', allowInsecure) } : {}),
    scopes,
    ...(doc.idTokenSignedResponseAlg ? { idTokenSignedResponseAlg: doc.idTokenSignedResponseAlg } : {}),
    par,
    clockToleranceSec: doc.clockToleranceSec ?? 30,
    maxIdTokenAgeSec: doc.maxIdTokenAgeSec ?? 600,
    allowInsecure,
    ...(tlsCa ? { tlsCa } : {}),
    ...(signals ? {} : { signals: false as const }),
    ...(ssf ? { ssf } : {}),
  };
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
