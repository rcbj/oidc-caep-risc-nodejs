// A confidential OpenID Connect relying party: Authorization Code (OIDC Core section 3.1) with PKCE
// (RFC 7636), a client secret or private_key_jwt at the token endpoint, and the checks RFC 9700 asks
// for. The browser only ever carries a code. Tokens stay in this process.

import { createHash, timingSafeEqual } from 'node:crypto';
import type { JWTVerifyGetKey } from 'jose';
import { applyClientAuth, loadPrivateKey, type SigningKey } from './client-auth.ts';
import { readConfigFile, type ResolvedConfig } from './config.ts';
import { discoverProvider, type ProviderMetadata } from './discovery.ts';
import { OidcError } from './errors.ts';
import { send, type TlsOptions } from './http.ts';
import { fetchJwks, idTokenAlgorithms, validateIdToken } from './id-token.ts';
import { codeChallengeS256, randomToken } from './pkce.ts';

const FRONT_CHANNEL_TOKENS = ['access_token', 'id_token', 'refresh_token', 'token_type'];

/** What one sign-in established. The tokens are for this process; do not put them in a page. */
export interface OidcLogin {
  subject: string;
  issuer: string;
  email?: string;
  name?: string;
  preferredUsername?: string;
  /** The provider's session id, the ID token `sid` claim, when it sent one. */
  sid?: string;
  claims: Record<string, unknown>;
  accessToken: string;
  refreshToken?: string;
  idToken: string;
  tokenType: string;
  /** When the access token expires, from `expires_in`. */
  expiresAt?: Date;
  scope?: string;
}

/** What the application keeps between the redirect to the provider and the callback. */
export interface Transaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  maxAge?: number;
  /** Set when this sign-in must come back as the same subject (signing that account in again). */
  expectedSub?: string;
}

export interface AuthorizeOptions {
  redirectUri?: string;
  scope?: string;
  /** `login` asks the provider to authenticate again, which is how a second account is added. */
  prompt?: string;
  loginHint?: string;
  maxAge?: number;
  acrValues?: string;
  expectedSub?: string;
}

/** The redirect to send the browser to, and the transaction to store until the callback. */
export interface AuthorizeRequest extends Transaction {
  /** The provider's authorization endpoint, with the request or a `request_uri` from PAR. */
  url: string;
}

export interface RefreshOptions {
  scope?: string;
  /** The sign-in being refreshed. A new ID token's subject is checked against it. */
  previous?: OidcLogin;
}

export interface ClientCredentials {
  accessToken: string;
  tokenType: string;
  expiresAt?: Date;
  scope?: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

function same(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function claimString(claims: Record<string, unknown>, name: string): string | undefined {
  const value = claims[name];
  return typeof value === 'string' && value ? value : undefined;
}

function paramsOf(callback: URLSearchParams | Record<string, string | undefined>): URLSearchParams {
  if (callback instanceof URLSearchParams) return callback;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(callback)) if (value !== undefined) params.set(key, value);
  return params;
}

/**
 * A confidential OpenID Connect client. Build it with {@link RelyingParty.fromFile} or
 * {@link RelyingParty.create}; both load the provider's metadata before returning.
 */
export class RelyingParty {
  readonly config: ResolvedConfig;
  /** The provider's metadata, loaded by {@link RelyingParty.create}. */
  readonly metadata: ProviderMetadata;
  readonly #key: SigningKey | undefined;
  #jwks: JWTVerifyGetKey | undefined;
  #algorithms: string[];
  readonly #usedCodes = new Map<string, number>();
  #clientCredentials: { scope: string; token: ClientCredentials; until: number } | undefined;

  private constructor(config: ResolvedConfig, metadata: ProviderMetadata, key: SigningKey | undefined) {
    this.config = config;
    this.metadata = metadata;
    this.#key = key;
    this.#algorithms = idTokenAlgorithms(metadata.id_token_signing_alg_values_supported, config.idTokenSignedResponseAlg);
  }

  /** Reads a configuration file, discovers the provider, and returns a client. */
  static async fromFile(path: string): Promise<RelyingParty> {
    return RelyingParty.create(readConfigFile(path));
  }

  /** Discovers the provider (or uses metadata already loaded) and returns a client. */
  static async create(config: ResolvedConfig): Promise<RelyingParty> {
    if (config.tokenEndpointAuthMethod === 'private_key_jwt' && !config.privateKeyPem) {
      throw new OidcError('config', 'private_key_jwt needs a private key');
    }
    if (config.tokenEndpointAuthMethod !== 'private_key_jwt' && !config.clientSecret) {
      throw new OidcError('config', `${config.tokenEndpointAuthMethod} needs a client secret`);
    }
    const tls = config.tlsCa ? { ca: config.tlsCa } : {};
    if (!config.allowInsecure) {
      for (const [name, value] of [['issuer', config.issuer], ['metadataUrl', config.metadataUrl]] as const) {
        if (value && new URL(value.startsWith('http') ? value : `https://${value}`).protocol === 'http:' && name === 'issuer') {
          throw new OidcError('config', 'issuer must use https (set allowInsecure for a development provider)');
        }
      }
    }
    let metadata = config.metadata;
    if (!metadata) {
      if (!config.metadataUrl) throw new OidcError('config', 'metadataUrl or metadata is required');
      if (!config.allowInsecure && new URL(config.metadataUrl).protocol !== 'https:') {
        throw new OidcError('config', 'metadataUrl must use https (set allowInsecure for a development provider)');
      }
      metadata = await discoverProvider(config.metadataUrl, tls);
    }
    if (!config.allowInsecure) {
      for (const [name, value] of Object.entries(metadata)) {
        if (typeof value === 'string' && value.startsWith('http:') && name.endsWith('endpoint') || name === 'jwks_uri' && typeof value === 'string' && value.startsWith('http:') || name === 'issuer' && typeof value === 'string' && value.startsWith('http:')) {
          throw new OidcError('discovery', `${name} must use https: ${value}`);
        }
      }
    }
    const methods = metadata.token_endpoint_auth_methods_supported;
    if (methods && !methods.includes(config.tokenEndpointAuthMethod)) {
      throw new OidcError('discovery', `the provider does not advertise ${config.tokenEndpointAuthMethod}`);
    }
    const challenges = metadata.code_challenge_methods_supported;
    if (challenges && !challenges.includes('S256')) throw new OidcError('discovery', 'the provider does not advertise PKCE S256');
    const key = config.privateKeyPem ? await loadPrivateKey(config.privateKeyPem, config.privateKeyAlg) : undefined;
    return new RelyingParty(config, metadata, key);
  }

  /** PEM trust anchors for calls to this provider, when the configuration named one. */
  tls(): TlsOptions {
    return this.config.tlsCa ? { ca: this.config.tlsCa } : {};
  }

  /**
   * Builds the Authentication Request. Store the returned transaction (everything except `url`) with
   * the browser until {@link RelyingParty.complete}. With `par` of `auto` or `always`, the parameters
   * go to the pushed authorization endpoint first when the provider has one.
   */
  async authorize(options: AuthorizeOptions = {}): Promise<AuthorizeRequest> {
    const redirectUri = options.redirectUri ?? this.config.redirectUri;
    const scope = options.scope ?? this.config.scopes;
    const state = randomToken();
    const nonce = randomToken();
    const codeVerifier = randomToken();
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallengeS256(codeVerifier),
      code_challenge_method: 'S256',
    });
    if (options.prompt) params.set('prompt', options.prompt);
    if (options.loginHint) params.set('login_hint', options.loginHint);
    if (options.maxAge !== undefined) params.set('max_age', String(options.maxAge));
    if (options.acrValues) params.set('acr_values', options.acrValues);
    const transaction: Transaction = {
      state, nonce, codeVerifier, redirectUri,
      ...(options.maxAge !== undefined ? { maxAge: options.maxAge } : {}),
      ...(options.expectedSub ? { expectedSub: options.expectedSub } : {}),
    };
    const par = this.metadata.pushed_authorization_request_endpoint;
    const usePar = this.config.par === 'always' || (this.config.par === 'auto' && !!par);
    if (this.config.par === 'always' && !par) throw new OidcError('discovery', 'par is always, and the provider has no pushed authorization endpoint');
    if (usePar && par) {
      const pushed = await this.#form(par, params);
      const requestUri = typeof pushed.request_uri === 'string' ? pushed.request_uri : '';
      if (!requestUri) throw new OidcError('protocol', 'the pushed authorization response has no request_uri');
      const url = new URL(this.metadata.authorization_endpoint);
      url.searchParams.set('client_id', this.config.clientId);
      url.searchParams.set('request_uri', requestUri);
      return { ...transaction, url: url.href };
    }
    const url = new URL(this.metadata.authorization_endpoint);
    for (const [key, value] of params) url.searchParams.set(key, value);
    return { ...transaction, url: url.href };
  }

  /**
   * Exchanges the code from the redirect URI. `callback` is that URI's query. `transaction` is what
   * {@link RelyingParty.authorize} returned for this browser. A code is accepted once.
   */
  async complete(callback: URLSearchParams | Record<string, string | undefined>, transaction: Transaction): Promise<OidcLogin> {
    const params = paramsOf(callback);
    for (const name of FRONT_CHANNEL_TOKENS) {
      if (params.has(name)) throw new OidcError('validation', `${name} was returned on the redirect, and a code-flow client refuses it`);
    }
    if (params.get('error')) {
      const description = params.get('error_description');
      throw new OidcError('protocol', description ? `${params.get('error')}: ${description}` : String(params.get('error')), { oauthError: params.get('error') ?? undefined });
    }
    const state = params.get('state') ?? '';
    if (!transaction.state || !same(state, transaction.state)) throw new OidcError('validation', 'the callback state does not match this sign-in');
    const iss = params.get('iss');
    if (iss !== null && iss !== this.metadata.issuer) throw new OidcError('validation', `iss mismatch in the callback: ${iss}`);
    if (iss === null && this.metadata.authorization_response_iss_parameter_supported) {
      throw new OidcError('validation', 'iss is missing from the callback, and the provider requires it');
    }
    const code = params.get('code');
    if (!code) throw new OidcError('validation', 'the callback has no code');
    this.#rememberCode(code);
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: transaction.redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    const tokens = await this.#token(body);
    if (!tokens.id_token) throw new OidcError('protocol', 'the token response has no id_token');
    const claims = await this.#idToken(tokens.id_token, {
      nonce: transaction.nonce,
      accessToken: tokens.access_token,
      code,
      ...(transaction.maxAge !== undefined ? { maxAge: transaction.maxAge } : {}),
    });
    if (transaction.expectedSub && claims.sub !== transaction.expectedSub) {
      throw new OidcError('validation', 'the provider signed in a different account from the one requested');
    }
    return loginFrom(tokens, claims);
  }

  /**
   * Refresh Token grant. A new ID token, when the provider sends one, is held to `previous` (the same
   * subject and issuer). The previous refresh token is kept when the provider does not rotate it.
   */
  async refresh(refreshToken: string, options: RefreshOptions = {}): Promise<OidcLogin> {
    if (!refreshToken) throw new OidcError('protocol', 'there is no refresh token');
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    if (options.scope) body.set('scope', options.scope);
    const tokens = await this.#token(body);
    const previous = options.previous;
    let claims = previous?.claims;
    let idToken = tokens.id_token ?? previous?.idToken;
    if (tokens.id_token) {
      if (!previous) throw new OidcError('validation', 'the refresh returned an ID token and there is no previous sign-in to check it against');
      claims = await this.#idToken(tokens.id_token, { accessToken: tokens.access_token, previousSub: previous.subject });
      idToken = tokens.id_token;
    }
    if (!claims || !idToken || !previous && !tokens.id_token) {
      throw new OidcError('protocol', 'the refresh returned no ID token and no previous sign-in was given');
    }
    return loginFrom({ ...tokens, refresh_token: tokens.refresh_token ?? refreshToken, id_token: idToken }, claims);
  }

  /**
   * Client Credentials grant, for a call this application makes as itself (the Shared Signals stream).
   * The token is cached until shortly before it expires.
   */
  async clientCredentials(scope = 'ssf.manage'): Promise<ClientCredentials> {
    const now = Date.now();
    if (this.#clientCredentials && this.#clientCredentials.scope === scope && this.#clientCredentials.until > now) {
      return this.#clientCredentials.token;
    }
    const body = new URLSearchParams({ grant_type: 'client_credentials', scope });
    const tokens = await this.#token(body);
    const token = credentialsFrom(tokens);
    const until = token.expiresAt ? token.expiresAt.getTime() - 30_000 : now + 60_000;
    this.#clientCredentials = { scope, token, until };
    return token;
  }

  /** Calls UserInfo with the access token and checks that `sub` is `expectedSub`. */
  async userinfo(accessToken: string, expectedSub: string): Promise<Record<string, unknown>> {
    if (!expectedSub) throw new OidcError('validation', 'userinfo needs the subject to check the response against');
    if (!this.metadata.userinfo_endpoint) throw new OidcError('discovery', 'the provider has no userinfo_endpoint');
    const answer = await send(this.metadata.userinfo_endpoint, {
      headers: { accept: 'application/json, application/jwt', authorization: `Bearer ${accessToken}` },
    }, this.tls(), 'protocol');
    if (answer.status === 401) throw new OidcError('protocol', 'userinfo refused the access token', { oauthError: 'invalid_token' });
    if (answer.status !== 200) throw new OidcError('protocol', `userinfo answered ${answer.status}`);
    let claims: Record<string, unknown>;
    if (answer.contentType.includes('application/jwt')) {
      claims = await this.#idToken(answer.body.trim(), { algorithms: this.#algorithms });
    } else {
      let body: unknown;
      try {
        body = JSON.parse(answer.body);
      } catch (err) {
        throw new OidcError('protocol', 'userinfo did not answer JSON', { cause: err });
      }
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new OidcError('validation', 'userinfo did not answer a JSON object');
      claims = body as Record<string, unknown>;
    }
    if (claims.sub !== expectedSub) throw new OidcError('validation', 'userinfo sub does not match the ID token sub');
    return claims;
  }

  /**
   * The RP-Initiated Logout URL, or `undefined` when the provider has no end-session endpoint.
   * Ending the provider's session signs every account in this browser out of it; end one local
   * session without redirecting there.
   */
  endSessionUrl(options: { idToken?: string; postLogoutRedirectUri?: string; state?: string; logoutHint?: string } = {}): string | undefined {
    if (!this.metadata.end_session_endpoint) return undefined;
    const url = new URL(this.metadata.end_session_endpoint);
    const redirect = options.postLogoutRedirectUri ?? this.config.postLogoutRedirectUri;
    if (options.idToken) url.searchParams.set('id_token_hint', options.idToken);
    if (redirect) url.searchParams.set('post_logout_redirect_uri', redirect);
    url.searchParams.set('client_id', this.config.clientId);
    if (options.logoutHint) url.searchParams.set('logout_hint', options.logoutHint);
    if (options.state) url.searchParams.set('state', options.state);
    return url.href;
  }

  async #idToken(token: string, extra: { nonce?: string; accessToken?: string; code?: string; maxAge?: number; previousSub?: string; algorithms?: string[] }): Promise<Record<string, unknown>> {
    const checks = {
      issuer: this.metadata.issuer,
      clientId: this.config.clientId,
      algorithms: extra.algorithms ?? this.#algorithms,
      jwks: await this.#keys(),
      clockToleranceSec: this.config.clockToleranceSec,
      maxIdTokenAgeSec: this.config.maxIdTokenAgeSec,
      ...(this.config.clientSecret ? { clientSecret: this.config.clientSecret } : {}),
      ...extra,
    };
    try {
      return await validateIdToken(token, checks);
    } catch (err) {
      if (!(err instanceof OidcError) || err.code !== 'signature') throw err;
      this.#jwks = undefined;
      return validateIdToken(token, { ...checks, jwks: await this.#keys(true) });
    }
  }

  async #keys(force = false): Promise<JWTVerifyGetKey> {
    if (!force && this.#jwks) return this.#jwks;
    this.#jwks = await fetchJwks(this.metadata.jwks_uri, this.tls());
    return this.#jwks;
  }

  async #token(body: URLSearchParams): Promise<TokenResponse> {
    const parsed = await this.#form(this.metadata.token_endpoint, body);
    const access = parsed.access_token;
    const tokenType = parsed.token_type;
    if (typeof access !== 'string' || !access) throw new OidcError('protocol', 'the token response has no access_token');
    if (typeof tokenType !== 'string' || !tokenType) throw new OidcError('protocol', 'the token response has no token_type');
    if (/^dpop$/i.test(tokenType)) throw new OidcError('protocol', 'the provider returned a DPoP token; this client asked for a Bearer token');
    if (!/^bearer$/i.test(tokenType)) throw new OidcError('protocol', `the token response token_type is ${tokenType}`);
    return {
      access_token: access,
      token_type: tokenType,
      ...(typeof parsed.id_token === 'string' ? { id_token: parsed.id_token } : {}),
      ...(typeof parsed.refresh_token === 'string' ? { refresh_token: parsed.refresh_token } : {}),
      ...(typeof parsed.expires_in === 'number' ? { expires_in: parsed.expires_in } : {}),
      ...(typeof parsed.scope === 'string' ? { scope: parsed.scope } : {}),
    };
  }

  /** A form POST with this client's authentication. The audience of a client assertion is the issuer. */
  async #form(url: string, body: URLSearchParams): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' };
    await applyClientAuth(this.config, this.#key, body, headers, this.metadata.issuer);
    const answer = await send(url, { method: 'POST', headers, body: body.toString() }, this.tls(), 'protocol');
    let parsed: unknown;
    try {
      parsed = answer.body ? JSON.parse(answer.body) : {};
    } catch (err) {
      throw new OidcError('protocol', `${url} answered ${answer.status} with no JSON`, { cause: err });
    }
    const doc = parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
    if (answer.status !== 200 && answer.status !== 201) {
      const oauthError = typeof doc.error === 'string' ? doc.error : undefined;
      const description = typeof doc.error_description === 'string' ? doc.error_description : '';
      throw new OidcError('protocol', `${url} answered ${answer.status}${oauthError ? `: ${oauthError}` : ''}${description ? `: ${description}` : ''}`, oauthError ? { oauthError } : {});
    }
    return doc;
  }

  /** Refuses a code this process has already exchanged. Recorded before the token request, so a replay never spends it twice. */
  #rememberCode(code: string): void {
    const now = Date.now();
    const cutoff = now - 10 * 60_000;
    for (const [hash, at] of this.#usedCodes) if (at < cutoff) this.#usedCodes.delete(hash);
    const hash = createHash('sha256').update(code).digest('hex');
    if (this.#usedCodes.has(hash)) throw new OidcError('validation', 'this authorization code was already used');
    this.#usedCodes.set(hash, now);
  }
}

function loginFrom(tokens: TokenResponse, claims: Record<string, unknown>): OidcLogin {
  const email = claimString(claims, 'email');
  const name = claimString(claims, 'name');
  const preferredUsername = claimString(claims, 'preferred_username');
  const sid = claimString(claims, 'sid');
  return {
    subject: String(claims.sub),
    issuer: String(claims.iss),
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(preferredUsername ? { preferredUsername } : {}),
    ...(sid ? { sid } : {}),
    claims,
    accessToken: tokens.access_token,
    ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
    idToken: tokens.id_token ?? '',
    tokenType: tokens.token_type,
    ...(tokens.expires_in !== undefined ? { expiresAt: new Date(Date.now() + tokens.expires_in * 1000) } : {}),
    ...(tokens.scope ? { scope: tokens.scope } : {}),
  };
}

function credentialsFrom(tokens: TokenResponse): ClientCredentials {
  return {
    accessToken: tokens.access_token,
    tokenType: tokens.token_type,
    ...(tokens.expires_in !== undefined ? { expiresAt: new Date(Date.now() + tokens.expires_in * 1000) } : {}),
    ...(tokens.scope ? { scope: tokens.scope } : {}),
  };
}
