// Which of the application's own sessions belong to which person, and to which provider session.
// A Shared Signals event names the provider's view — a person by their subject, a session by the
// provider's session id (the ID token `sid`) — and this index turns that into local sessions to end.

import type { OidcLogin } from '../relying-party.ts';

/** What one of the application's sessions is known by. */
export interface TrackedSession {
  /** The application's own session id. */
  localId: string;
  /** The person's subject (`sub`). */
  person?: string | undefined;
  /** The person's email, for an event whose subject is an `email`. Compared without case. */
  email?: string | undefined;
  /** The provider's session id: the ID token `sid`. */
  idpSession?: string | undefined;
  /** When the application's session ends anyway; the index forgets it then. */
  expiresAt?: Date | undefined;
}

/**
 * Where the receiver looks up sessions. The default is one process's memory; an application that runs
 * several processes gives every one of them the same index, so an event one process receives ends a
 * session another process created.
 */
export interface SessionIndex {
  add(session: TrackedSession): void | Promise<void>;
  remove(localId: string): void | Promise<void>;
  byPerson(person: string): string[] | Promise<string[]>;
  byEmail(email: string): string[] | Promise<string[]>;
  byIdpSession(idpSession: string): string[] | Promise<string[]>;
}

/** One process's memory, bounded: expired sessions go first, then the oldest. */
export class MemorySessionIndex implements SessionIndex {
  readonly #sessions = new Map<string, TrackedSession>();
  readonly #max: number;

  constructor(max = 100_000) {
    this.#max = max;
  }

  add(session: TrackedSession): void {
    if (this.#sessions.size >= this.#max && !this.#sessions.has(session.localId)) {
      const now = Date.now();
      for (const [key, value] of this.#sessions) if (value.expiresAt && value.expiresAt.getTime() <= now) this.#sessions.delete(key);
      while (this.#sessions.size >= this.#max) {
        const oldest = this.#sessions.keys().next().value;
        if (oldest === undefined) break;
        this.#sessions.delete(oldest);
      }
    }
    this.#sessions.set(session.localId, { ...session, email: session.email?.toLowerCase() });
  }

  remove(localId: string): void {
    this.#sessions.delete(localId);
  }

  #find(match: (session: TrackedSession) => boolean): string[] {
    const now = Date.now();
    const out: string[] = [];
    for (const [key, value] of this.#sessions) {
      if (value.expiresAt && value.expiresAt.getTime() <= now) {
        this.#sessions.delete(key);
        continue;
      }
      if (match(value)) out.push(key);
    }
    return out;
  }

  byPerson(person: string): string[] {
    return this.#find((session) => session.person === person);
  }

  byEmail(email: string): string[] {
    const wanted = email.toLowerCase();
    return this.#find((session) => session.email === wanted);
  }

  byIdpSession(idpSession: string): string[] {
    return this.#find((session) => session.idpSession === idpSession);
  }
}

/** What an OpenID Connect sign-in says about the session, for the index. */
export function trackedFromLogin(localId: string, login: OidcLogin, expiresAt?: Date): TrackedSession {
  return {
    localId,
    person: login.subject,
    ...(login.email ? { email: login.email } : {}),
    ...(login.sid ? { idpSession: login.sid } : {}),
    ...(expiresAt ? { expiresAt } : {}),
  };
}
