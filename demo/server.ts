// The demo: a traditional server-rendered web application that signs people in with OpenID Connect
// through oidc-caep-risc-nodejs. node:http and nothing else; Node runs this TypeScript file as it is.
//
// SEVERAL PEOPLE IN ONE BROWSER. The browser holds one cookie, `aset`, naming an ACCOUNT SET: the people
// signed in to it, each a session of their own (their own OpenID Connect login, events and live channel).
// Which one a tab shows is in its URL, `/u/<account>/`, an id stable for as long as that person stays
// signed in, so two tabs can show two people at once and an account that ends never makes another tab
// show someone else.
//
//   GET  /                to the first account's page, or the sign-in page when nobody is signed in
//   GET  /u/<a>/          that account's page; ?tab=events shows its CAEP and RISC events and the stream
//   GET  /login           the authorization request; ?add=1 adds another person (prompt=login);
//                         ?account=<a> signs that person in again (prompt=login, login_hint, expected sub)
//   GET  /callback        the redirect URI: exchanges the code, then 303 to that account's page
//   GET  /u/<a>/events    Server-Sent Events for that account: each event about THAT account, as JSON
//   GET  /u/<a>/api/signals  the same events as JSON (?after=<id>)
//   POST /u/<a>/signals/verify  asks the provider for a verification event, for that account
//   POST /u/<a>/signals/clear   empties that account's event log
//   POST /u/<a>/logout    signs that account out of this application; the others stay
//   POST /logout          signs every account in this browser out of this application
//   GET  /healthz         for the container's health check
//
// SHARED SIGNALS: with an `ssf` block, and unless `signals` is false, the demo is a CAEP and RISC
// receiver (the library's SignalsReceiver). One poll stream, authenticated by a Bearer token from the
// client-credentials grant (scope ssf.manage). `signals: false` does not start the receiver and does
// not contact a transmitter. An event that revokes a session, or disables, purges or compromises an
// account, ends the matching local sessions, and their open tabs are told at once.
//
// Two cookies. `oidc_txn` holds the outstanding transactions (state, nonce, code verifier), HMAC-signed,
// scoped to /callback, SameSite=Lax: the provider brings the browser back with a top-level GET, which
// sends a Lax cookie. `aset` is the account set, SameSite=Lax, set after the callback.
// Access tokens and refresh tokens stay in this process. The pages never render them.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EVENT, OidcError, RelyingParty, SignalsReceiver, resolveConfig, trackedFromLogin,
  type OidcLogin, type SignalEvent, type Transaction,
} from 'oidc-caep-risc-nodejs';
import { onPort } from '../scripts/redirects.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const CONFIG = resolve(process.env.OIDC_CONFIG || resolve(here, 'oidc.json'));
const SECRET = process.env.SESSION_SECRET ? Buffer.from(process.env.SESSION_SECRET) : randomBytes(32);
const SESSION_MS = 8 * 3600_000;
const MAX_SESSIONS = 10_000;
const STYLES = readFileSync(resolve(here, 'public/styles.css'));
const APP_JS = readFileSync(resolve(here, 'public/app.js'));
const loaded = (() => {
  try {
    return JSON.parse(readFileSync(CONFIG, 'utf8')) as {
      signals?: unknown;
      ssf?: { transmitter?: string; pollIntervalMs?: number };
    };
  } catch {
    return undefined;
  }
})();
const signalsOff = loaded?.signals === false;
const SSF = !signalsOff && loaded?.ssf?.transmitter ? loaded.ssf : undefined;

// The relying party is built on first use and again after a failure, so the demo starts (and is
// healthy) before the provider is reachable or the setup script has written the client secret.
let rpPromise: Promise<RelyingParty> | undefined;
function relyingParty(): Promise<RelyingParty> {
  rpPromise ??= loadRelyingParty().then((rp) => {
    startReceiver(rp);
    return rp;
  }, (err: unknown) => {
    rpPromise = undefined;
    throw err;
  });
  return rpPromise;
}

async function loadRelyingParty(): Promise<RelyingParty> {
  const raw = JSON.parse(readFileSync(CONFIG, 'utf8')) as Record<string, unknown>;
  // An offline metadata document (the CI smoke test) stands in for discovery.
  if (process.env.OIDC_METADATA_FILE) {
    raw.metadataFile = process.env.OIDC_METADATA_FILE;
    delete raw.metadataUrl;
    delete raw.issuer;
  }
  // A loopback redirect follows the port this process listens on, which is the URI configure-iya-sts
  // registers. A public redirect is left as written.
  for (const key of ['redirectUri', 'redirect_uri', 'postLogoutRedirectUri', 'post_logout_redirect_uri']) {
    if (typeof raw[key] === 'string' && raw[key]) raw[key] = onPort(raw[key], PORT);
  }
  return RelyingParty.create(resolveConfig(raw, dirname(CONFIG)));
}

/** One received event, as the events tab draws it and the browser receives it. */
interface LoggedEvent {
  id: number;
  at: string;
  type: string;
  family: 'CAEP' | 'RISC' | 'SSF';
  ended: boolean;
  about: 'session' | 'stream';
  subject: string;
  members: Record<string, unknown>;
  jti: string;
}

interface Session {
  login: OidcLogin;
  expires: number;
  setId: string;
  account: string;
  signals: LoggedEvent[];
}
const sessions = new Map<string, Session>();
const accountSets = new Map<string, string[]>();

function endSession(sid: string): void {
  const s = sessions.get(sid);
  sessions.delete(sid);
  if (!s) return;
  const set = accountSets.get(s.setId);
  if (set) {
    const left = set.filter((x) => x !== sid);
    if (left.length) accountSets.set(s.setId, left);
    else accountSets.delete(s.setId);
  }
}
const listeners = new Map<string, Set<ServerResponse>>();

function tell(sid: string, event: string, data: unknown, id?: number): void {
  for (const res of listeners.get(sid) ?? []) {
    res.write(`${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (event === 'signed-out') res.end();
  }
  if (event === 'signed-out') listeners.delete(sid);
}

const shortType = (uri: string) => uri.replace(/^.*\/event-type\//, '');
const familyOf = (uri: string): LoggedEvent['family'] => (/\/caep\//.test(uri) ? 'CAEP' : /\/risc\//.test(uri) ? 'RISC' : 'SSF');
// The heading and the account list show the directory uid. The subject stays the protocol
// subject, which is what Shared Signals match. A code-flow ID token omits profile claims, so
// the uid is UserInfo `preferred_username` (filled below). The access token's `username`
// claim is that same uid when UserInfo does not return one.
const who = (login: OidcLogin) => login.preferredUsername || login.email || login.subject;

function accessUsername(token: string): string | undefined {
  const payload = token.split('.')[1];
  if (!payload) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString()) as { username?: unknown };
    return typeof claims.username === 'string' && claims.username ? claims.username : undefined;
  } catch {
    return undefined;
  }
}

async function withUsername(rp: RelyingParty, login: OidcLogin): Promise<OidcLogin> {
  let preferred = login.preferredUsername;
  let email = login.email;
  let name = login.name;
  let claims = login.claims;
  try {
    const info = await rp.userinfo(login.accessToken, login.subject);
    if (typeof info.preferred_username === 'string' && info.preferred_username) preferred = info.preferred_username;
    if (!email && typeof info.email === 'string' && info.email) email = info.email;
    if (!name && typeof info.name === 'string' && info.name) name = info.name;
    claims = { ...login.claims, ...info };
  } catch (err) {
    // The sign-in still stands. The page shows the subject until a username is known.
    console.warn(`userinfo: ${(err as Error).message}`);
  }
  if (!preferred) preferred = accessUsername(login.accessToken);
  return {
    ...login,
    claims,
    ...(preferred ? { preferredUsername: preferred } : {}),
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
  };
}

const LOG_SIZE = 25;
let sequence = 0;
const verificationsAsked = new Map<string, string>();
let streamStatus: { status: string; reason?: unknown; at: string } | undefined;

function logFor(sid: string, entry: LoggedEvent): void {
  const s = sessions.get(sid);
  if (!s) return;
  s.signals.unshift(entry);
  s.signals.length = Math.min(s.signals.length, LOG_SIZE);
  tell(sid, 'signal', entry, entry.id);
}

let receiver: SignalsReceiver | undefined;
let receiverState = signalsOff
  ? 'not configured (signals are off)'
  : SSF ? 'starting' : 'not configured (no ssf block in the configuration file)';
function startReceiver(rp: RelyingParty): void {
  if (rp.config.signals === false || !SSF || receiver) return;
  const r = new SignalsReceiver({
    transmitter: SSF.transmitter!,
    tls: rp.tls(),
    headers: async () => {
      const creds = await rp.clientCredentials('ssf.manage');
      return { authorization: `Bearer ${creds.accessToken}` };
    },
    description: `oidc-caep-risc-nodejs demo (${rp.config.clientId})`,
    ...(SSF.pollIntervalMs ? { pollIntervalMs: SSF.pollIntervalMs } : {}),
    onEndSessions: (ids: string[], event: SignalEvent) => {
      for (const sid of ids) {
        endSession(sid);
        tell(sid, 'signed-out', { type: shortType(event.type), reason: event.payload.reason_user ?? event.payload.reason_admin ?? event.payload.reason ?? null });
      }
      console.log(`ssf: ${shortType(event.type)} ended ${ids.length} local session(s)`);
    },
  });
  r.on('*', (event: SignalEvent) => {
    const entry: LoggedEvent = {
      id: ++sequence,
      at: new Date().toISOString(),
      type: event.type,
      family: familyOf(event.type),
      ended: event.ended,
      about: 'session',
      subject: [event.subject.person, event.subject.email, event.subject.idpSession && `IdP session ${event.subject.idpSession}`]
        .filter(Boolean).join(', '),
      members: event.payload,
      jti: event.jti,
    };
    if (event.type === EVENT.verification) {
      const asker = verificationsAsked.get(String(event.payload.state ?? ''));
      verificationsAsked.delete(String(event.payload.state ?? ''));
      if (asker) logFor(asker, { ...entry, about: 'stream' });
      console.log(`ssf: verification received${asker ? '' : ' (asked by no session here)'}`);
      return;
    }
    if (event.type === EVENT.streamUpdated) {
      streamStatus = { status: String(event.payload.status ?? ''), reason: event.payload.reason, at: entry.at };
      for (const sid of listeners.keys()) tell(sid, 'stream', streamStatus);
      return;
    }
    if (!event.ended) for (const sid of event.sessions) logFor(sid, entry);
  });
  receiver = r;
  r.start().then(() => {
    receiverState = `polling stream ${r.stream?.stream_id} at ${SSF.transmitter}`;
  }, (err: Error) => {
    receiverState = `not running: ${err.message}`;
    receiver = undefined;
    console.warn(`ssf: the receiver did not start: ${err.message}`);
  });
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const mac = (value: string) => createHmac('sha256', SECRET).update(value).digest('base64url');

function sealed(value: unknown): string {
  const body = Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${body}.${mac(body)}`;
}

function unseal<T>(token: string | undefined): T | undefined {
  if (!token) return undefined;
  const [body, tag] = token.split('.');
  if (!body || !tag) return undefined;
  const want = Buffer.from(mac(body));
  const got = Buffer.from(tag);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return undefined;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString()) as T;
  } catch {
    return undefined;
  }
}

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

// Secure on an https deployment and on localhost, which browsers treat as a secure context.
let secureCookies = true;

function cookie(name: string, value: string, opts: { path?: string; maxAge?: number }): string {
  return [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path ?? '/'}`, 'HttpOnly', 'SameSite=Lax',
    ...(secureCookies ? ['Secure'] : []), ...(opts.maxAge !== undefined ? [`Max-Age=${opts.maxAge}`] : [])].join('; ');
}

function accountsOf(req: IncomingMessage): Array<{ sid: string; session: Session }> {
  return accountsOfSet(cookies(req).aset);
}

function accountsOfSet(setId: string | undefined): Array<{ sid: string; session: Session }> {
  const out: Array<{ sid: string; session: Session }> = [];
  for (const sid of (setId && accountSets.get(setId)) || []) {
    const session = sessions.get(sid);
    if (!session) continue;
    if (session.expires <= Date.now()) {
      endSession(sid);
      void receiver?.untrack(sid);
      continue;
    }
    out.push({ sid, session });
  }
  return out;
}

function accountOf(req: IncomingMessage, account: string): { sid: string; session: Session } | undefined {
  return accountsOf(req).find((x) => x.session.account === account);
}

const samePerson = (a: OidcLogin, b: OidcLogin) => a.issuer === b.issuer && a.subject === b.subject;

function send(res: ServerResponse, status: number, body: string | Buffer, headers: Record<string, string | string[]> = {}): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ...headers,
  });
  res.end(body);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a href="/">oidc-caep-risc-nodejs demo</a></header><main>
${body}
</main><footer>A traditional web application signing in with OpenID Connect through <a href="https://www.npmjs.com/package/oidc-caep-risc-nodejs">oidc-caep-risc-nodejs</a>.</footer></body>
</html>
`;
}

type Tab = 'identity' | 'events';

function tabs(base: string, active: Tab, count = 0): string {
  const tab = (id: Tab, label: string) =>
    `<a class="page-tab" role="tab" href="${base}/?tab=${id}" aria-selected="${id === active}"${id === active ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<nav class="page-tabs" role="tablist" aria-label="Sections">${tab('identity', 'Identity')}${tab('events', `CAEP &amp; RISC events <span class="count" id="signal-count">${count || ''}</span>`)}</nav>`;
}

function member(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    const values = Object.values(value as Record<string, unknown>);
    if (values.length && values.every((v) => typeof v === 'string')) return values.join(' / ');
    return JSON.stringify(value);
  }
  return String(value);
}

function logItem(e: LoggedEvent): string {
  const members = Object.entries(e.members)
    .filter(([k]) => k !== 'subject')
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(member(v))}</td></tr>`).join('');
  const outcome = e.about === 'stream' ? 'about the stream: the verification this session asked for' : e.ended ? 'ended this session' : 'recorded; this session continues';
  return `<li class="log-item" data-id="${e.id}">
  <div class="log-top"><span class="badge ${e.family.toLowerCase()}">${e.family}</span> <strong>${esc(shortType(e.type))}</strong> <time>${esc(e.at)}</time></div>
  <p class="log-outcome${e.ended ? ' ended' : ''}">${esc(outcome)}</p>
  ${e.subject ? `<p><small>Subject: ${esc(e.subject)}</small></p>` : ''}
  ${members ? `<table class="facts members">${members}</table>` : ''}
  <p><small>jti ${esc(e.jti)}</small></p>
</li>`;
}

function eventsPanel(base: string, session: Session, notice?: string): string {
  const stream = receiver?.stream;
  const delivered = (stream?.events_delivered ?? []) as string[];
  const lastId = session.signals[0]?.id ?? 0;
  return `<section class="card">
<h2>Shared Signals stream</h2>
${notice ? `<p class="notice">${esc(notice)}</p>` : ''}
<table class="facts">
<tr><th>Receiver</th><td>${esc(receiverState)}</td></tr>
<tr><th>Stream status</th><td id="stream-status">${esc(streamStatus ? `${streamStatus.status} (${streamStatus.at})` : 'enabled')}</td></tr>
${stream ? `<tr><th>Stream</th><td>${esc(stream.stream_id)}<br><small>poll delivery (RFC 8936) at ${esc(stream.delivery?.endpoint_url)}</small></td></tr>
<tr><th>Authentication</th><td>Bearer access token from the client credentials grant (ssf.manage)</td></tr>
<tr><th>Delivers</th><td>${delivered.map((t) => `<span class="badge ${familyOf(t).toLowerCase()}">${familyOf(t)}</span> ${esc(shortType(t))}`).join('<br>') || '(nothing yet)'}</td></tr>` : ''}
<tr><th>Ends this session on</th><td>session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked</td></tr>
</table>
${stream ? `<form method="post" action="${base}/signals/verify" class="inline" id="verify-form"><button type="submit">Request verification event</button></form>` : ''}
</section>
<section class="card">
<h2>Event log</h2>
<p><small>The CAEP and RISC events about this session or its person, newest first, and the verification events this session asked for. Each appears here within moments of the receiver getting it: <span id="live-state">connecting…</span></small></p>
<ol class="log" id="log" data-last-id="${lastId}">${session.signals.map((e) => logItem(e)).join('')}</ol>
<p class="empty" id="log-empty"${session.signals.length ? ' hidden' : ''}>No CAEP or RISC event about this session yet. At the identity provider, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>
<form method="post" action="${base}/signals/clear" class="inline"><button type="submit" class="secondary">Clear this session's log</button></form>
</section>`;
}

function accountBar(accounts: Array<{ session: Session }>, current: Session): string {
  const items = accounts.map(({ session: a }) => a === current
    ? `<li aria-current="true"><strong>${esc(who(a.login))}</strong></li>`
    : `<li><a href="/u/${esc(a.account)}/">${esc(who(a.login))}</a></li>`).join('');
  return `<nav class="accounts" aria-label="Accounts in this browser">
<span class="accounts-label">Signed in here:</span> <ul>${items}</ul>
<a class="button small" href="/login?add=1">Add another account</a>
${accounts.length > 1 ? '<form method="post" action="/logout" class="inline"><button type="submit" class="secondary small">Sign out of all accounts</button></form>' : ''}
</nav>`;
}

function claimRows(login: OidcLogin): string {
  const claims = login.claims;
  const rows: Array<[string, string]> = [];
  if (login.preferredUsername) rows.push(['Username', login.preferredUsername]);
  rows.push(['Subject', login.subject], ['Issuer', login.issuer]);
  if (login.email) rows.push(['Email', login.email]);
  if (login.name) rows.push(['Name', login.name]);
  if (login.sid) rows.push(['Provider session', login.sid]);
  if (typeof claims.auth_time === 'number') rows.push(['Authenticated', new Date(claims.auth_time * 1000).toISOString()]);
  if (claims.acr) rows.push(['acr', String(claims.acr)]);
  if (Array.isArray(claims.amr)) rows.push(['amr', claims.amr.map(String).join(', ')]);
  return rows.map(([name, value]) => `<tr><th>${esc(name)}</th><td>${esc(value)}</td></tr>`).join('');
}

function home(session: Session | undefined, rp: RelyingParty | undefined, problem?: string, tab: Tab = 'identity', notice?: string,
  accounts: Array<{ session: Session }> = [], gone?: string): string {
  if (session) {
    const base = `/u/${session.account}`;
    const l = session.login;
    const identity = `<table class="facts">${claimRows(l)}</table>
<p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p>`;
    const count = session.signals.length;
    return page('Signed in', `<h1>Signed in as ${esc(who(l))}</h1>
${accountBar(accounts, session)}
${gone ? `<p class="notice">${esc(gone)}</p>` : ''}
${tabs(base, tab, count)}
<p id="signal-banner" class="problem" hidden></p>
<p id="signal-toast" class="notice" hidden></p>
<div role="tabpanel" id="panel" data-base="${base}" data-tab="${tab}" data-last-id="${session.signals[0]?.id ?? 0}">${tab === 'events' ? eventsPanel(base, session, notice) : identity}</div>
<form method="post" action="${base}/logout" class="inline"><button type="submit">Sign out of this account</button></form>
<script src="/app.js"></script>`);
  }
  return page('Sign in', `<h1>Sign in with OpenID Connect</h1>
${problem ? `<p class="problem">${esc(problem)}</p>` : ''}
<p>This application is a confidential client${rp ? ` of ${esc(rp.metadata.issuer)}` : ''}. It sends the browser to the authorization endpoint
(Authorization Code, PKCE S256, <code>client_secret_basic</code>) and takes the tokens on the back channel.
The scopes are the same ones <code>oidc-caep-client</code> asks for.</p>
<p class="buttons"><a class="button primary" href="/login">Sign in with OpenID Connect</a></p>`);
}

interface Pending {
  txns: Transaction[];
  /** The account set when the sign-in began, in case the callback is the first request that carries it. */
  set?: string;
}

function sameState(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://demo.invalid');
  const method = req.method ?? 'GET';

  if (url.pathname === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain' });
  if (url.pathname === '/styles.css') return send(res, 200, STYLES, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'max-age=300' });
  if (url.pathname === '/app.js') return send(res, 200, APP_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'max-age=300' });

  const scoped = /^\/u\/([A-Za-z0-9_-]{6,32})(\/.*)?$/.exec(url.pathname);
  const hereAccount = scoped ? accountOf(req, scoped[1] ?? '') : undefined;
  const sub = scoped ? (scoped[2] ?? '/') : undefined;

  if (scoped && !hereAccount) {
    if (sub === '/api/signals') return send(res, 401, JSON.stringify({ signedIn: false }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    if (sub === '/events') return send(res, 204, '');
    res.writeHead(303, { location: '/?gone=1', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/events' && method === 'GET') {
    const sid = hereAccount.sid;
    res.writeHead(200, {
      'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no', 'referrer-policy': 'no-referrer',
    });
    const after = Number(req.headers['last-event-id'] ?? url.searchParams.get('after') ?? 0) || 0;
    res.write('retry: 2000\n\n');
    for (const e of [...hereAccount.session.signals].reverse()) if (e.id > after) res.write(`id: ${e.id}\nevent: signal\ndata: ${JSON.stringify(e)}\n\n`);
    if (streamStatus) res.write(`event: stream\ndata: ${JSON.stringify(streamStatus)}\n\n`);
    const set = listeners.get(sid) ?? new Set<ServerResponse>();
    set.add(res);
    listeners.set(sid, set);
    const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(keepAlive);
      set.delete(res);
      if (!set.size) listeners.delete(sid);
    });
    return;
  }

  if (hereAccount && sub === '/api/signals' && method === 'GET') {
    const session = hereAccount.session;
    const after = Number(url.searchParams.get('after') ?? 0) || 0;
    const events = [...session.signals].reverse().filter((e) => e.id > after);
    return send(res, 200, JSON.stringify({ signedIn: true, events, lastId: session.signals[0]?.id ?? after, streamStatus: streamStatus ?? null }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
  }

  if (url.pathname === '/' && method === 'GET') {
    const first = accountsOf(req)[0];
    if (first) {
      res.writeHead(303, { location: `/u/${first.session.account}/${url.searchParams.get('gone') ? '?gone=1' : ''}`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
  }

  if ((url.pathname === '/' || (hereAccount && sub === '/')) && method === 'GET') {
    const session = hereAccount?.session;
    let rp: RelyingParty | undefined;
    let problem: string | undefined;
    try {
      rp = await relyingParty();
    } catch (err) {
      problem = `The relying party is not configured yet: ${(err as Error).message}. Run the setup script (npm run configure-iya-sts).`;
    }
    const tab = url.searchParams.get('tab') === 'events' ? 'events' : 'identity';
    const notice = url.searchParams.get('verify') === 'sent'
      ? 'Verification event requested; it shows in the log within a few seconds.'
      : url.searchParams.get('verify') === 'failed' ? 'The identity provider refused the verification request; see the demo\'s log.' : undefined;
    const gone = url.searchParams.get('gone') ? 'The account you opened is no longer signed in here.' : undefined;
    return send(res, 200, home(session, rp, gone && !session ? gone : problem, tab, notice, accountsOf(req), gone), session ? {
      'content-security-policy': "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    } : {});
  }

  if (url.pathname === '/login' && method === 'GET') {
    const rp = await relyingParty();
    const again = url.searchParams.get('account') ? accountOf(req, url.searchParams.get('account')!) : undefined;
    const add = url.searchParams.get('add') === '1';
    const hint = again ? (again.session.login.preferredUsername || again.session.login.email) : undefined;
    const request = await rp.authorize({
      ...(add || again ? { prompt: 'login' } : {}),
      ...(hint ? { loginHint: hint } : {}),
      ...(again ? { expectedSub: again.session.login.subject } : {}),
    });
    const before = unseal<Pending>(cookies(req).oidc_txn)?.txns ?? [];
    const setNow = cookies(req).aset;
    const txns = [request, ...before].slice(0, 3).map(({ url: _url, ...txn }) => txn);
    const pending = cookie('oidc_txn', sealed({ txns, ...(setNow && accountSets.has(setNow) ? { set: setNow } : {}) }), { path: '/callback', maxAge: 600 });
    res.writeHead(302, { location: request.url, 'set-cookie': pending, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    res.end();
    return;
  }

  if (url.pathname === '/callback' && method === 'GET') {
    const rp = await relyingParty();
    const pending = unseal<Pending>(cookies(req).oidc_txn);
    const clearPending = cookie('oidc_txn', '', { path: '/callback', maxAge: 0 });
    const state = url.searchParams.get('state') ?? '';
    const txn = pending?.txns.find((t) => sameState(t.state, state));
    try {
      if (!txn) throw new OidcError('validation', 'this callback is not a sign-in this browser started');
      const login = await withUsername(rp, await rp.complete(url.searchParams, txn));
      if (sessions.size >= MAX_SESSIONS) {
        for (const [k, s] of sessions) if (s.expires <= Date.now()) sessions.delete(k);
      }
      if (sessions.size >= MAX_SESSIONS) throw new Error('too many sessions');
      const sid = randomBytes(32).toString('base64url');
      const until = Date.now() + SESSION_MS;
      const oldSetId = pending?.set ?? cookies(req).aset;
      const accounts = accountsOfSet(oldSetId);
      const existing = accounts.find((a) => samePerson(a.session.login, login));
      const account = existing?.session.account ?? randomBytes(9).toString('base64url');
      if (existing) {
        endSession(existing.sid);
        await receiver?.untrack(existing.sid);
        tell(existing.sid, 'replaced', {});
      }
      const setId = randomBytes(32).toString('base64url');
      const order = accounts.map((a) => (a.sid === existing?.sid ? sid : a.sid));
      if (!existing) order.push(sid);
      if (oldSetId) accountSets.delete(oldSetId);
      accountSets.set(setId, order);
      for (const x of order) {
        const s = x === sid ? undefined : sessions.get(x);
        if (s) s.setId = setId;
      }
      sessions.set(sid, { login, expires: until, signals: [], setId, account });
      await receiver?.track(trackedFromLogin(sid, login, new Date(until)));
      console.log(`signed in ${who(login)} (${login.subject}); ${order.length} account(s) in this browser`);
      const longest = Math.max(...order.map((x) => sessions.get(x)?.expires ?? 0));
      res.writeHead(303, {
        location: `/u/${account}/`,
        'set-cookie': [clearPending, cookie('aset', setId, { maxAge: Math.floor((longest - Date.now()) / 1000) })],
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
      });
      res.end();
    } catch (err) {
      const what = err instanceof OidcError ? `${err.code}: ${err.message}` : (err as Error).message;
      console.warn(`sign-in refused: ${what}`);
      send(res, 400, page('Sign-in failed', `<h1>Sign-in failed</h1><p class="problem">${esc(what)}</p><p><a href="/">Start again</a></p>`), { 'set-cookie': clearPending });
    }
    return;
  }

  if (hereAccount && sub === '/signals/verify' && method === 'POST') {
    let outcome = 'failed';
    const sid = hereAccount.sid;
    if (receiver?.stream) {
      try {
        const state = randomBytes(12).toString('base64url');
        verificationsAsked.set(state, sid);
        if (verificationsAsked.size > 1000) verificationsAsked.delete(verificationsAsked.keys().next().value!);
        await receiver.verify(state);
        outcome = 'sent';
      } catch (err) {
        console.warn(`ssf: verification request refused: ${(err as Error).message}`);
      }
    }
    if (String(req.headers.accept ?? '').includes('application/json')) {
      return send(res, outcome === 'sent' ? 202 : 502, JSON.stringify({ outcome }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    }
    res.writeHead(303, { location: `/u/${hereAccount.session.account}/?tab=events&verify=${outcome}`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/signals/clear' && method === 'POST') {
    hereAccount.session.signals = [];
    res.writeHead(303, { location: `/u/${hereAccount.session.account}/?tab=events`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/logout' && method === 'POST') {
    endSession(hereAccount.sid);
    await receiver?.untrack(hereAccount.sid);
    tell(hereAccount.sid, 'signed-out', {});
    res.writeHead(303, { location: '/', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (url.pathname === '/logout' && method === 'POST') {
    for (const { sid } of accountsOf(req)) {
      endSession(sid);
      await receiver?.untrack(sid);
      tell(sid, 'signed-out', {});
    }
    res.writeHead(303, { location: '/', 'set-cookie': cookie('aset', '', { maxAge: 0 }), 'cache-control': 'no-store' });
    res.end();
    return;
  }

  send(res, 404, page('Not found', '<h1>Not found</h1>'));
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err: Error) => {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', `<h1>Something went wrong</h1><p class="problem">${esc(err.message)}</p><p><a href="/">Home</a></p>`));
    else res.end();
  });
});

try {
  const config = JSON.parse(readFileSync(CONFIG, 'utf8')) as { redirectUri?: string };
  const redirect = new URL(config.redirectUri ?? 'http://localhost/');
  secureCookies = redirect.protocol === 'https:' || redirect.hostname === 'localhost' || redirect.hostname === '127.0.0.1';
} catch (err) {
  console.warn(`cannot read ${CONFIG}: ${(err as Error).message}`);
}

server.listen(PORT, () => console.log(`oidc-caep-risc-nodejs demo on port ${PORT}, configuration ${CONFIG}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    receiver?.stop();
    server.close(() => process.exit(0));
  });
}
