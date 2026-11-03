// The tokens of completed sign-ins, keyed by a session id the application chooses. The relying
// party writes an entry when a sign-in completes, reads it when the application asks for a valid
// access token, rewrites it after a refresh, and removes it at sign-out or when a refresh fails.

/** What the cache holds for one session. Plain JSON, so that a shared store can serialize it. */
export interface CachedSession {
  subject: string;
  issuer: string;
  idToken: string;
  claims: Record<string, unknown>;
  accessToken: string;
  tokenType: string;
  refreshToken?: string;
  /** When the access token expires, in milliseconds since the epoch. Absent when the provider sent no `expires_in`. */
  expiresAt?: number;
  scope?: string;
}

/**
 * Where the relying party keeps sign-in tokens. The default is one process's memory; an application
 * that runs several processes gives each of them one shared store.
 */
export interface TokenStore {
  get(session: string): CachedSession | undefined | Promise<CachedSession | undefined>;
  set(session: string, tokens: CachedSession): void | Promise<void>;
  delete(session: string): void | Promise<void>;
}

/** One process's memory, bounded: the oldest entry goes first. */
export class MemoryTokenStore implements TokenStore {
  readonly #entries = new Map<string, CachedSession>();
  readonly #max: number;

  constructor(max = 100_000) {
    this.#max = max;
  }

  get(session: string): CachedSession | undefined {
    return this.#entries.get(session);
  }

  set(session: string, tokens: CachedSession): void {
    this.#entries.delete(session);
    while (this.#entries.size >= this.#max) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    this.#entries.set(session, tokens);
  }

  delete(session: string): void {
    this.#entries.delete(session);
  }

  /** How many sessions are held. */
  get size(): number {
    return this.#entries.size;
  }
}
