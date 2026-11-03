// A confidential OpenID Connect relying party: Authorization Code (OIDC Core section 3.1) with PKCE
// (RFC 7636), a client secret or private_key_jwt at the token endpoint, DPoP (RFC 9449) when the
// provider offers it, and the checks RFC 9700 asks for. The browser only ever carries a code. Tokens
// stay in this process, in a per-session cache the application reads a valid access token from.

import { createHash, timingSafeEqual } from 'node:crypto';
import type { JWTVerifyGetKey } from 'jose';
import { applyClientAuth, loadPrivateKey, type SigningKey } from './client-auth.ts';
import { checkRedirectUri, finishConfig, readConfigFile, type RelyingPartyConfig, type ResolvedConfig } from './config.ts';
import { discoverProvider, type ProviderMetadata } from './discovery.ts';
import { DPOP_ALG, DpopSigner, asksForNonce } from './dpop.ts';
import { OidcError, type OidcErrorCode } from './errors.ts';
import { send, type HttpAnswer, type TlsOptions } from './http.ts';
import { fetchJwks, idTokenAlgorithms, validateIdToken } from './id-token.ts';
import { codeChallengeS256, randomToken } from './pkce.ts';
import { MemoryTokenStore, type CachedSession, type TokenStore } from './token-store.ts';

/** An access token is renewed when it has this little time left. */
const RENEW_BEFORE_MS = 30_000;

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
  /**
   * The session these tokens are cached under, after {@link RelyingParty.complete}: the id the
   * application passed, or one made for it. {@link RelyingParty.accessToken} takes it.
   */
  session?: string;
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
  /** The `acr_values` requested. The ID token's `acr` must be one of them. */
  acrValues?: string[];
}

export interface AuthorizeOptions {
  redirectUri?: string;
  scope?: string;
  /** `login` asks the provider to authenticate again, which is how a second account is added. */
  prompt?: string;
  loginHint?: string;
  maxAge?: number;
  /** Replaces the configured `acrValues` for this request: space-separated. */
  acrValues?: string;
  expectedSub?: string;
}

export interface CompleteOptions {
  /**
   * The application's id for the session this sign-in starts. The tokens are cached under it. When
   * omitted, one is made and returned as {@link OidcLogin.session}.
   */
  session?: string;
}

/** Options that are objects rather than configuration. */
export interface RelyingPartyOptions {
  /** Where sign-in tokens are cached. Default: this process's memory. */
  tokenStore?: TokenStore;
}

/** An access token and how to present it: `Bearer`, or `DPoP` with a proof. */
export interface AccessToken {
  accessToken: string;
  tokenType: string;
  expiresAt?: Date;
  scope?: string;
}

/** A request to a resource server, made by {@link RelyingParty.fetchResource}. */
export interface ResourceRequest {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
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

/** A client-credentials token: an {@link AccessToken}. */
export type ClientCredentials = AccessToken;

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
  readonly #dpop: DpopSigner | undefined;
  readonly #store: TokenStore;
  readonly #renewing = new Map<string, Promise<AccessToken>>();
  #jwks: JWTVerifyGetKey | undefined;
  #algorithms: string[];
  readonly #usedCodes = new Map<string, number>();
  #clientCredentials: { scope: string; token: ClientCredentials; until: number } | undefined;

  private constructor(config: ResolvedConfig, metadata: ProviderMetadata, key: SigningKey | undefined,
    dpop: DpopSigner | undefined, store: TokenStore) {
    this.config = config;
    this.metadata = metadata;
    this.#key = key;
    this.#dpop = dpop;
    this.#store = store;
    this.#algorithms = idTokenAlgorithms(metadata.id_token_signing_alg_values_supported, config.idTokenSignedResponseAlg, config.idTokenSigningAlgs);
  }

  /** Reads a configuration file, discovers the provider, and returns a client. */
  static async fromFile(path: string, options: RelyingPartyOptions = {}): Promise<RelyingParty> {
    return RelyingParty.create(readConfigFile(path), options);
  }

  /**
   * Discovers the provider (or uses metadata already loaded) and returns a client. A configuration
   * built by hand gets the same defaults and checks as one read from a file.
   */
  static async create(input: RelyingPartyConfig, options: RelyingPartyOptions = {}): Promise<RelyingParty> {
    const config = finishConfig(input);
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
    const parEndpoint = metadata.pushed_authorization_request_endpoint;
    if (metadata.require_pushed_authorization_requests) {
      if (config.par === 'never') throw new OidcError('config', 'par is never, and the provider requires pushed authorization requests');
      if (!parEndpoint) throw new OidcError('discovery', 'the provider requires pushed authorization requests and has no pushed authorization endpoint');
    }
    if (config.par === 'always' && !parEndpoint) throw new OidcError('discovery', 'par is always, and the provider has no pushed authorization endpoint');
    const dpopAlgs = metadata.dpop_signing_alg_values_supported;
    const dpopOffered = !!dpopAlgs && dpopAlgs.includes(DPOP_ALG);
    if (config.dpop === 'always' && !dpopOffered) {
      throw new OidcError('discovery', dpopAlgs
        ? `dpop is always, and the provider does not accept ${DPOP_ALG} proofs (${dpopAlgs.join(', ')})`
        : 'dpop is always, and the provider does not advertise dpop_signing_alg_values_supported');
    }
    const dpop = config.dpop !== 'never' && dpopOffered ? await DpopSigner.create(config.dpopKeyPem) : undefined;
    const key = config.privateKeyPem ? await loadPrivateKey(config.privateKeyPem, config.privateKeyAlg) : undefined;
    return new RelyingParty(config, metadata, key, dpop, options.tokenStore ?? new MemoryTokenStore());
  }

  /** Whether this client sends DPoP proofs, and so receives DPoP-bound tokens. */
  get usesDpop(): boolean {
    return !!this.#dpop;
  }

  /** The DPoP key's JWK thumbprint (the `dpop_jkt` sent), or `undefined` when DPoP is not in use. */
  get dpopThumbprint(): string | undefined {
    return this.#dpop?.thumbprint;
  }

  /**
   * A DPoP proof for one request, for an application that makes the call itself. `accessToken` adds
   * `ath`. Throws when DPoP is not in use.
   */
  async dpopProof(method: string, url: string, accessToken?: string): Promise<string> {
    if (!this.#dpop) throw new OidcError('config', 'DPoP is not in use');
    return this.#dpop.proof(method, url, accessToken);
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
    const redirectUri = options.redirectUri === undefined ? this.config.redirectUri : checkRedirectUri(options.redirectUri, 'redirectUri');
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
    const acr = (options.acrValues ?? this.config.acrValues ?? '').split(/\s+/).filter(Boolean);
    if (acr.length) params.set('acr_values', acr.join(' '));
    if (this.#dpop) params.set('dpop_jkt', this.#dpop.thumbprint);
    const transaction: Transaction = {
      state, nonce, codeVerifier, redirectUri,
      ...(options.maxAge !== undefined ? { maxAge: options.maxAge } : {}),
      ...(options.expectedSub ? { expectedSub: options.expectedSub } : {}),
      ...(acr.length ? { acrValues: acr } : {}),
    };
    const par = this.metadata.pushed_authorization_request_endpoint;
    // create() refused `never` against a provider that requires PAR, and `always` without an endpoint.
    const usePar = this.config.par !== 'never' && !!par;
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
  async complete(callback: URLSearchParams | Record<string, string | undefined>, transaction: Transaction,
    options: CompleteOptions = {}): Promise<OidcLogin> {
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
      ...(transaction.acrValues && transaction.acrValues.length ? { acrValues: transaction.acrValues } : {}),
    });
    if (transaction.expectedSub && claims.sub !== transaction.expectedSub) {
      throw new OidcError('validation', 'the provider signed in a different account from the one requested');
    }
    const login = loginFrom(tokens, claims);
    const session = options.session ?? randomToken();
    await this.#store.set(session, cachedFrom(login));
    return { ...login, session };
  }

  /**
   * A valid access token for a session {@link RelyingParty.complete} cached: the cached one while it
   * has more than 30 seconds left, otherwise one from the refresh token (with a DPoP proof when DPoP
   * is in use), which replaces the cached tokens. A session that is not cached, or whose refresh
   * fails, is refused; a failed refresh also removes the session.
   */
  async accessToken(session: string): Promise<AccessToken> {
    const cached = await this.#store.get(session);
    if (!cached) throw new OidcError('validation', 'there are no tokens for this session; sign in again');
    if (cached.expiresAt === undefined || cached.expiresAt - Date.now() > RENEW_BEFORE_MS) return accessTokenOf(cached);
    const running = this.#renewing.get(session);
    if (running) return running;
    const renewal = this.#renew(session, cached).finally(() => this.#renewing.delete(session));
    this.#renewing.set(session, renewal);
    return renewal;
  }

  /** The tokens cached for a session, or `undefined`. They are this process's; never put them in a page. */
  async sessionTokens(session: string): Promise<OidcLogin | undefined> {
    const cached = await this.#store.get(session);
    return cached ? { ...loginOf(cached), session } : undefined;
  }

  /** Forgets a session's tokens: at sign-out, or when a CAEP event ends the session. */
  async removeSession(session: string): Promise<void> {
    await this.#store.delete(session);
  }

  async #renew(session: string, cached: CachedSession): Promise<AccessToken> {
    if (!cached.refreshToken) {
      await this.#store.delete(session);
      throw new OidcError('protocol', 'the access token has expired and there is no refresh token; sign in again');
    }
    let login: OidcLogin;
    try {
      login = await this.refresh(cached.refreshToken, { previous: loginOf(cached) });
    } catch (err) {
      await this.#store.delete(session);
      if (err instanceof OidcError) throw err;
      throw new OidcError('protocol', `the refresh failed: ${(err as Error).message}`, { cause: err });
    }
    const renewed = cachedFrom(login);
    await this.#store.set(session, renewed);
    return accessTokenOf(renewed);
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

  /**
   * Calls UserInfo with the access token and checks that `sub` is `expectedSub`. `tokenType` is how the
   * token is presented; the default is `DPoP` when DPoP is in use, otherwise `Bearer`.
   */
  async userinfo(accessToken: string, expectedSub: string, options: { tokenType?: string } = {}): Promise<Record<string, unknown>> {
    if (!expectedSub) throw new OidcError('validation', 'userinfo needs the subject to check the response against');
    if (!this.metadata.userinfo_endpoint) throw new OidcError('discovery', 'the provider has no userinfo_endpoint');
    const tokenType = options.tokenType ?? (this.#dpop ? 'DPoP' : 'Bearer');
    const answer = await this.fetchResource(this.metadata.userinfo_endpoint, {
      headers: { accept: 'application/json, application/jwt' },
    }, { accessToken, tokenType });
    if (answer.status === 401) throw new OidcError('protocol', 'userinfo refused the access token', { oauthError: 'invalid_token' });
    if (answer.status !== 200) throw new OidcError('protocol', `userinfo answered ${answer.status}`);
    let claims: Record<string, unknown>;
    if (answer.contentType.includes('application/jwt')) {
      claims = await this.#idToken(answer.body.trim(), { algorithms: this.#algorithms, requireTypAndAtHash: false });
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
   * A request to a resource server with an access token. A `DPoP` token goes as `Authorization: DPoP`
   * with a proof carrying `ath`; a `Bearer` token as `Authorization: Bearer`. A 401 that asks for a
   * DPoP nonce is retried once with the nonce it gave. TLS is the provider's trust chain.
   */
  async fetchResource(url: string, init: ResourceRequest, token: Pick<AccessToken, 'accessToken' | 'tokenType'>,
    code: OidcErrorCode = 'protocol', tls: TlsOptions = this.tls()): Promise<HttpAnswer> {
    const dpop = /^dpop$/i.test(token.tokenType);
    if (!dpop && !/^bearer$/i.test(token.tokenType)) throw new OidcError('config', `cannot present a ${token.tokenType} token`);
    if (dpop && !this.#dpop) throw new OidcError('config', 'a DPoP-bound token needs DPoP, and this client is not using it');
    const method = (init.method ?? 'GET').toUpperCase();
    for (let attempt = 0; ; attempt++) {
      const headers: Record<string, string> = { ...(init.headers ?? {}) };
      if (dpop) {
        headers.authorization = `DPoP ${token.accessToken}`;
        headers.dpop = await this.#dpop!.proof(method, url, token.accessToken);
      } else {
        headers.authorization = `Bearer ${token.accessToken}`;
      }
      const answer = await send(url, { method, headers, ...(init.body !== undefined ? { body: init.body } : {}) }, tls, code);
      this.#dpop?.remember(url, answer);
      if (dpop && attempt === 0 && asksForNonce(answer) && this.#dpop!.nonceFor(url)) continue;
      return answer;
    }
  }

  /**
   * What a {@link SignalsReceiver} sends its calls with (its `request` option): each call carries a
   * client-credentials token for `scope`, as a DPoP-bound token with a proof when DPoP is in use.
   * A 401 that is not a nonce challenge drops the cached token, so the next call gets a new one.
   */
  signalsRequest(scope = 'ssf.manage', tls: TlsOptions = this.tls()):
    (method: string, url: string, init: { headers?: Record<string, string>; body?: string }) => Promise<HttpAnswer> {
    return async (method, url, init) => {
      const token = await this.clientCredentials(scope);
      const answer = await this.fetchResource(url, { method, ...init }, token, 'ssf', tls);
      if (answer.status === 401) this.#clientCredentials = undefined;
      return answer;
    };
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

  async #idToken(token: string, extra: { nonce?: string; accessToken?: string; code?: string; maxAge?: number;
    previousSub?: string; algorithms?: string[]; acrValues?: string[]; requireTypAndAtHash?: boolean }): Promise<Record<string, unknown>> {
    const checks = {
      requireTypAndAtHash: this.config.requireIdTokenTypAndAtHash,
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
    // A proof went with every token request when DPoP is in use, so the token must be DPoP-bound;
    // without one it must be a Bearer token (RFC 9449 section 5).
    if (this.#dpop && !/^dpop$/i.test(tokenType)) throw new OidcError('protocol', `a DPoP proof was sent and the token_type is ${tokenType}, not DPoP`);
    if (!this.#dpop && !/^bearer$/i.test(tokenType)) throw new OidcError('protocol', `no DPoP proof was sent and the token_type is ${tokenType}, not Bearer`);
    return {
      access_token: access,
      token_type: tokenType,
      ...(typeof parsed.id_token === 'string' ? { id_token: parsed.id_token } : {}),
      ...(typeof parsed.refresh_token === 'string' ? { refresh_token: parsed.refresh_token } : {}),
      ...(typeof parsed.expires_in === 'number' ? { expires_in: parsed.expires_in } : {}),
      ...(typeof parsed.scope === 'string' ? { scope: parsed.scope } : {}),
    };
  }

  /**
   * A form POST with this client's authentication, and a DPoP proof when DPoP is in use. The audience
   * of a client assertion is the issuer. A 400 `use_dpop_nonce` is retried once with the nonce it gave.
   */
  async #form(url: string, body: URLSearchParams): Promise<Record<string, unknown>> {
    for (let attempt = 0; ; attempt++) {
      const form = new URLSearchParams(body);
      const headers: Record<string, string> = { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' };
      await applyClientAuth(this.config, this.#key, form, headers, this.metadata.issuer);
      if (this.#dpop) headers.dpop = await this.#dpop.proof('POST', url);
      const answer = await send(url, { method: 'POST', headers, body: form.toString() }, this.tls(), 'protocol');
      this.#dpop?.remember(url, answer);
      const doc = parseForm(url, answer);
      if (this.#dpop && attempt === 0 && answer.status === 400 && doc.error === 'use_dpop_nonce' && this.#dpop.nonceFor(url)) continue;
      return formResult(url, answer, doc);
    }
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

function parseForm(url: string, answer: HttpAnswer): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = answer.body ? JSON.parse(answer.body) : {};
  } catch (err) {
    throw new OidcError('protocol', `${url} answered ${answer.status} with no JSON`, { cause: err });
  }
  return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
}

function formResult(url: string, answer: HttpAnswer, doc: Record<string, unknown>): Record<string, unknown> {
  if (answer.status !== 200 && answer.status !== 201) {
    const oauthError = typeof doc.error === 'string' ? doc.error : undefined;
    const description = typeof doc.error_description === 'string' ? doc.error_description : '';
    throw new OidcError('protocol', `${url} answered ${answer.status}${oauthError ? `: ${oauthError}` : ''}${description ? `: ${description}` : ''}`, oauthError ? { oauthError } : {});
  }
  return doc;
}

function cachedFrom(login: OidcLogin): CachedSession {
  return {
    subject: login.subject,
    issuer: login.issuer,
    idToken: login.idToken,
    claims: login.claims,
    accessToken: login.accessToken,
    tokenType: login.tokenType,
    ...(login.refreshToken ? { refreshToken: login.refreshToken } : {}),
    ...(login.expiresAt ? { expiresAt: login.expiresAt.getTime() } : {}),
    ...(login.scope ? { scope: login.scope } : {}),
  };
}

function loginOf(cached: CachedSession): OidcLogin {
  const claims = cached.claims ?? {};
  const email = claimString(claims, 'email');
  const name = claimString(claims, 'name');
  const preferredUsername = claimString(claims, 'preferred_username');
  const sid = claimString(claims, 'sid');
  return {
    subject: cached.subject,
    issuer: cached.issuer,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(preferredUsername ? { preferredUsername } : {}),
    ...(sid ? { sid } : {}),
    claims,
    accessToken: cached.accessToken,
    ...(cached.refreshToken ? { refreshToken: cached.refreshToken } : {}),
    idToken: cached.idToken,
    tokenType: cached.tokenType,
    ...(cached.expiresAt !== undefined ? { expiresAt: new Date(cached.expiresAt) } : {}),
    ...(cached.scope ? { scope: cached.scope } : {}),
  };
}

function accessTokenOf(cached: CachedSession): AccessToken {
  return {
    accessToken: cached.accessToken,
    tokenType: cached.tokenType,
    ...(cached.expiresAt !== undefined ? { expiresAt: new Date(cached.expiresAt) } : {}),
    ...(cached.scope ? { scope: cached.scope } : {}),
  };
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
