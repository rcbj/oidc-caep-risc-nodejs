// A Shared Signals receiver for a server-side application (OpenID SSF 1.0, RFC 8936 poll delivery):
// the application's one stream carries CAEP and RISC events about every person who uses it, and each
// event is turned into the application's own sessions to end.
//
//   start()       finds the transmitter, finds this application's poll stream or creates it, and polls;
//   track()       after a sign-in: this local session belongs to this person and this provider session;
//   untrack()     after a sign-out;
//   onEndSessions the application's callback: these local sessions must end now;
//   on(type)      the application's handler for an event type.
//
// Authentication is the application's choice of headers (a Bearer token from the client-credentials
// grant, scope ssf.manage) or a TLS client certificate. Every SET is verified — signature against the
// transmitter's JWKS, iss, aud, typ — before anything acts on it, and acknowledged only once handled.

import { wellKnownUrls } from '../discovery.ts';
import { OidcError } from '../errors.ts';
import { send, type TlsOptions } from '../http.ts';
import { DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subjectOf, type SubjectRef } from './events.ts';
import { verifyCompactJws, type Jwk } from './jws.ts';
import { MemorySessionIndex, type SessionIndex, type TrackedSession } from './session-index.ts';

const POLL_METHOD = 'urn:ietf:rfc:8936';

/** One verified event, as handed to the application. */
export interface SignalEvent {
  /** The event type URI. */
  type: string;
  /** The event's own members (`initiating_entity`, `reason_admin`, `credential_type`, ...). */
  payload: Record<string, unknown>;
  /** Who and what it is about. */
  subject: SubjectRef;
  /** The SET's `jti`. */
  jti: string;
  iat?: number | undefined;
  txn?: string | undefined;
  /** The local sessions it names, whether or not they were ended. */
  sessions: string[];
  /** Whether the receiver ended them (the type is in `endOn`). */
  ended: boolean;
}

export interface SignalsReceiverOptions {
  /** The transmitter's issuer. Its configuration is read from `/.well-known/ssf-configuration`. */
  transmitter: string;
  /** TLS for every call: `ca` to trust, and `cert` + `key` to present (mutual TLS). */
  tls?: TlsOptions;
  /** Extra headers for every call, for example `authorization: Bearer …` from {@link RelyingParty.clientCredentials}. */
  headers?: () => Record<string, string> | Promise<Record<string, string>>;
  /** The event types to ask for. Default: the CAEP session and credential events and the RISC account events. */
  eventsRequested?: readonly string[];
  /** The event types that end the matching local sessions. */
  endOn?: readonly string[];
  /** Called with the local sessions an event ends. End them in the application's session store. */
  onEndSessions: (localIds: string[], event: SignalEvent) => void | Promise<void>;
  /** The session index. The default is this process's memory. */
  sessionIndex?: SessionIndex;
  /** A description of the stream, shown at the transmitter. */
  description?: string;
  /** How long to wait between polls when nothing was waiting, in milliseconds. Default 5000. */
  pollIntervalMs?: number;
  /** At most this many SETs per poll. Default 50. */
  maxEvents?: number;
  /** Where the receiver logs. Default console. */
  log?: Pick<Console, 'info' | 'warn' | 'error'>;
}

interface Configuration {
  issuer: string;
  jwks_uri: string;
  configuration_endpoint: string;
  verification_endpoint?: string;
  delivery_methods_supported?: string[];
}

interface StreamConfig {
  stream_id: string;
  aud?: string | string[];
  delivery?: { method?: string; endpoint_url?: string };
  events_delivered?: string[];
  events_requested?: string[];
}

export class SignalsReceiver {
  readonly #options: SignalsReceiverOptions & {
    eventsRequested: readonly string[];
    endOn: readonly string[];
    pollIntervalMs: number;
    maxEvents: number;
    log: Pick<Console, 'info' | 'warn' | 'error'>;
    transmitter: string;
  };
  readonly #index: SessionIndex;
  #config: Configuration | undefined;
  #stream: StreamConfig | undefined;
  #keys: Jwk[] = [];
  #keysAt = 0;
  #timer: NodeJS.Timeout | undefined;
  #running = false;
  #ack: string[] = [];
  #errs: Record<string, { err: string; description: string }> = {};
  #inflight: Promise<boolean> | undefined;
  readonly #handlers = new Map<string, Array<(event: SignalEvent) => void | Promise<void>>>();

  constructor(options: SignalsReceiverOptions) {
    if (!options || typeof options.onEndSessions !== 'function') throw new OidcError('config', 'onEndSessions is required');
    if (!/^https?:\/\//.test(options.transmitter ?? '')) throw new OidcError('config', 'transmitter must be an http(s) URL');
    this.#options = {
      eventsRequested: DEFAULT_EVENTS_REQUESTED,
      endOn: DEFAULT_ENDING_EVENTS,
      pollIntervalMs: 5000,
      maxEvents: 50,
      log: console,
      ...options,
      transmitter: options.transmitter.replace(/\/+$/, ''),
    };
    this.#index = options.sessionIndex ?? new MemorySessionIndex();
  }

  /** The stream the receiver is polling, once started. */
  get stream(): Readonly<StreamConfig> | undefined {
    return this.#stream;
  }

  /** Remembers a local session after a sign-in. */
  async track(session: TrackedSession): Promise<void> {
    await this.#index.add(session);
  }

  /** Forgets a local session, after a sign-out. */
  async untrack(localId: string): Promise<void> {
    await this.#index.remove(localId);
  }

  /** Adds a handler for one event type (`EVENT.*`), or `*` for every event. */
  on(type: string, handler: (event: SignalEvent) => void | Promise<void>): this {
    const list = this.#handlers.get(type) ?? [];
    list.push(handler);
    this.#handlers.set(type, list);
    return this;
  }

  async #call(method: string, url: string, body?: unknown): Promise<{ status: number; json: unknown }> {
    const headers: Record<string, string> = { accept: 'application/json', ...(await this.#options.headers?.()) };
    if (body !== undefined) headers['content-type'] = 'application/json';
    const answer = await send(url, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }, this.#options.tls ?? {}, 'ssf');
    let json: unknown;
    if (answer.body) {
      try {
        json = JSON.parse(answer.body);
      } catch {
        json = answer.body;
      }
    }
    return { status: answer.status, json };
  }

  async #discover(): Promise<Configuration> {
    const urls = wellKnownUrls(this.#options.transmitter, 'ssf-configuration');
    let last = new OidcError('ssf', `no transmitter configuration at ${urls.join(' or ')}`);
    for (const url of urls) {
      const answer = await this.#call('GET', url);
      const doc = answer.json as Configuration;
      if (answer.status === 404 && url !== urls[urls.length - 1]) continue;
      if (answer.status !== 200 || !doc || typeof doc !== 'object' || !doc.configuration_endpoint || !doc.jwks_uri) {
        last = new OidcError('ssf', `${url} answered ${answer.status} without a usable transmitter configuration`);
        continue;
      }
      if (doc.delivery_methods_supported && !doc.delivery_methods_supported.includes(POLL_METHOD)) {
        throw new OidcError('ssf', 'the transmitter does not offer poll delivery (RFC 8936)');
      }
      return doc;
    }
    throw last;
  }

  async #jwks(force = false): Promise<Jwk[]> {
    if (!force && this.#keys.length && Date.now() - this.#keysAt < 3_600_000) return this.#keys;
    const answer = await this.#call('GET', this.#config!.jwks_uri);
    const keys = (answer.json as { keys?: Jwk[] })?.keys;
    if (answer.status !== 200 || !Array.isArray(keys)) throw new OidcError('ssf', `the transmitter's JWKS answered ${answer.status}`);
    this.#keys = keys;
    this.#keysAt = Date.now();
    return keys;
  }

  /** Finds this receiver's poll stream, or creates it. */
  async #ensureStream(): Promise<StreamConfig> {
    const endpoint = this.#config!.configuration_endpoint;
    const listed = await this.#call('GET', endpoint);
    if (listed.status === 200) {
      const all = Array.isArray(listed.json) ? listed.json as StreamConfig[] : listed.json ? [listed.json as StreamConfig] : [];
      const mine = all.find((stream) => stream?.delivery?.method === POLL_METHOD && stream.stream_id);
      if (mine) return mine;
    } else if (listed.status !== 404) {
      throw new OidcError('ssf', `listing the streams at ${endpoint} answered ${listed.status}: ${JSON.stringify(listed.json).slice(0, 300)}`);
    }
    const created = await this.#call('POST', endpoint, {
      delivery: { method: POLL_METHOD },
      events_requested: this.#options.eventsRequested,
      ...(this.#options.description ? { description: this.#options.description } : {}),
    });
    const stream = created.json as StreamConfig;
    if ((created.status !== 200 && created.status !== 201) || !stream?.stream_id) {
      throw new OidcError('ssf', `creating a stream at ${endpoint} answered ${created.status}: ${JSON.stringify(created.json).slice(0, 300)}`);
    }
    return stream;
  }

  /** Finds the transmitter and the stream, then polls until {@link SignalsReceiver.stop}. */
  async start(): Promise<void> {
    if (this.#running) return;
    this.#config = await this.#discover();
    await this.#jwks(true);
    this.#stream = await this.#ensureStream();
    if (!this.#stream.delivery?.endpoint_url) throw new OidcError('ssf', 'the stream has no poll endpoint_url');
    this.#running = true;
    this.#options.log.info(`ssf: polling stream ${this.#stream.stream_id} at ${this.#stream.delivery.endpoint_url}, delivering ${(this.#stream.events_delivered ?? []).length} event type(s)`);
    void this.#loop();
  }

  /** Stops polling. Acknowledgements not yet sent go out on the next start's first poll. */
  stop(): void {
    this.#running = false;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  async #loop(): Promise<void> {
    if (!this.#running) return;
    let delay = this.#options.pollIntervalMs;
    try {
      const more = await this.pollOnce();
      if (more) delay = 0;
    } catch (err) {
      this.#options.log.warn(`ssf: poll failed: ${(err as Error).message}`);
      delay = Math.min(this.#options.pollIntervalMs * 4, 60_000);
    }
    if (this.#running) {
      this.#timer = setTimeout(() => void this.#loop(), delay);
      this.#timer.unref();
    }
  }

  /**
   * One poll. A call while a poll is in flight joins it: two overlapping polls would each be handed
   * every SET not yet acknowledged, and would handle each twice.
   */
  pollOnce(): Promise<boolean> {
    this.#inflight ??= this.#pollNow().finally(() => {
      this.#inflight = undefined;
    });
    return this.#inflight;
  }

  async #pollNow(): Promise<boolean> {
    const url = this.#stream!.delivery!.endpoint_url!;
    const ack = this.#ack.splice(0);
    const setErrs = this.#errs;
    this.#errs = {};
    const answer = await this.#call('POST', url, {
      maxEvents: this.#options.maxEvents,
      returnImmediately: true,
      ...(ack.length ? { ack } : {}),
      ...(Object.keys(setErrs).length ? { setErrs } : {}),
    });
    if (answer.status !== 200) {
      this.#ack.unshift(...ack);
      Object.assign(this.#errs, setErrs);
      throw new OidcError('ssf', `the poll answered ${answer.status}: ${JSON.stringify(answer.json).slice(0, 300)}`);
    }
    const body = (answer.json ?? {}) as { sets?: Record<string, string>; moreAvailable?: boolean };
    for (const [jti, token] of Object.entries(body.sets ?? {})) {
      try {
        await this.#handle(jti, token);
        this.#ack.push(jti);
      } catch (err) {
        const description = (err as Error).message;
        this.#options.log.warn(`ssf: SET ${jti} refused: ${description}`);
        this.#errs[jti] = { err: err instanceof OidcError && err.code === 'signature' ? 'invalid_key' : 'invalid_request', description };
      }
    }
    return !!body.moreAvailable;
  }

  async #handle(jti: string, token: string): Promise<void> {
    let verified;
    try {
      verified = verifyCompactJws(token, await this.#jwks());
    } catch (err) {
      if (!(err instanceof OidcError) || !/publishes no|does not verify/.test(err.message)) throw err;
      verified = verifyCompactJws(token, await this.#jwks(true));
    }
    const { header, payload } = verified;
    if (header.typ !== undefined && String(header.typ).toLowerCase() !== 'secevent+jwt') {
      throw new OidcError('validation', `the SET's typ is ${String(header.typ)}`);
    }
    if (payload.iss !== this.#config!.issuer) throw new OidcError('validation', `the SET was issued by ${String(payload.iss)}, not ${this.#config!.issuer}`);
    const want = ([] as string[]).concat(this.#stream!.aud ?? []);
    const aud = ([] as unknown[]).concat(payload.aud ?? []).map(String);
    if (want.length && !aud.some((one) => want.includes(one))) throw new OidcError('validation', `the SET is for ${aud.join(', ')}, not this stream`);
    if (payload.jti !== undefined && payload.jti !== jti) throw new OidcError('validation', 'the SET\'s jti is not the one it was delivered under');
    const events = payload.events as Record<string, Record<string, unknown>> | undefined;
    if (!events || typeof events !== 'object' || !Object.keys(events).length) throw new OidcError('validation', 'the SET carries no events');

    for (const [type, body] of Object.entries(events)) {
      const subject = subjectOf(payload.sub_id ?? body?.subject, this.#config!.issuer);
      const sessions = await this.#sessionsFor(type, subject);
      const ends = this.#options.endOn.includes(type) && sessions.length > 0;
      const event: SignalEvent = {
        type, payload: body ?? {}, subject, jti, sessions, ended: ends,
        iat: typeof payload.iat === 'number' ? payload.iat : undefined,
        txn: typeof payload.txn === 'string' ? payload.txn : undefined,
      };
      if (ends) {
        try {
          await this.#options.onEndSessions(sessions, event);
        } catch (err) {
          this.#options.log.error(`ssf: onEndSessions threw for ${type} (SET ${jti} is still acknowledged): ${(err as Error).message}`);
          event.ended = false;
        }
        if (event.ended) for (const id of sessions) await this.#index.remove(id);
      }
      for (const handler of [...(this.#handlers.get(type) ?? []), ...(this.#handlers.get('*') ?? [])]) {
        try {
          await handler(event);
        } catch (err) {
          this.#options.log.error(`ssf: a handler for ${type} threw (SET ${jti} is still acknowledged): ${(err as Error).message}`);
        }
      }
    }
  }

  /**
   * The local sessions an event names. A session event with a provider session names only the local
   * sessions started from it; otherwise every local session of the person (by subject, then email).
   */
  async #sessionsFor(type: string, subject: SubjectRef): Promise<string[]> {
    if (type === EVENT.verification || type === EVENT.streamUpdated) return [];
    if (subject.idpSession) {
      const found = await this.#index.byIdpSession(subject.idpSession);
      if (found.length || type === EVENT.sessionRevoked) return found;
    }
    if (subject.person) return this.#index.byPerson(subject.person);
    if (subject.email) return this.#index.byEmail(subject.email);
    return [];
  }

  /** Asks the transmitter for a verification event (SSF 1.0 section 8.1.4.2). */
  async verify(state?: string): Promise<void> {
    const endpoint = this.#config?.verification_endpoint;
    if (typeof endpoint !== 'string') throw new OidcError('ssf', 'the transmitter publishes no verification_endpoint');
    const answer = await this.#call('POST', endpoint, { stream_id: this.#stream!.stream_id, ...(state ? { state } : {}) });
    if (answer.status !== 200 && answer.status !== 204) throw new OidcError('ssf', `verification answered ${answer.status}`);
  }
}
