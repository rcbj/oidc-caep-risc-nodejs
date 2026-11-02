#!/usr/bin/env node
/**
 * Registers the demo as a confidential OpenID Connect client on a running iya-sts.
 *
 *   1. the client secret, if demo/generated/client-secret does not exist yet (32 bytes, created 0600).
 *      A re-run does not rotate it: an application that already exists is left with the secret it has;
 *   2. the listener's CA trust chain, written to the configuration's tlsCa file on every run. The
 *      bundle is GET /tls/server-certificate (leaf, intermediates, and the root). The handshake's
 *      chain is the fallback. The trust anchor's fingerprint is printed;
 *   3. the application, in the realm the metadata URL names: protocols oauth2 and oidc, response type
 *      code, grants authorization_code, refresh_token and client_credentials, the scopes from the
 *      configuration file, and token endpoint authentication client_secret_basic. No browser origin is
 *      registered: this client is a server, not a page;
 *   4. membership of SSF_READ and SSF_MANAGE for whichever of ssf.read and ssf.manage the scopes name.
 *      signals: false ignores those two scopes, so those roles are not registered and the test user
 *      is not put in those groups. No transmitter is registered. authn.multipleAccounts is set either way;
 *   5. a test user, oidc-demo-user, in ssf-read and ssf-manage when those scopes are in use. A
 *      password iya-sts generates for it is written to demo/generated/<user>.password (mode 0600),
 *      never printed; only that path is.
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/configure-iya-sts.ts
 *   node scripts/configure-iya-sts.ts --config demo/oidc.json --dry-run
 *
 * The management API token is minted as iya-sts's seeded client sts-api-client (client_credentials,
 * HTTP Basic), audienced to <base>/admin-api, scope admin:read admin:write. The secret is
 * ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.
 */

import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, fchmodSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { send } from '../packages/oidc-caep-risc-nodejs/src/http.ts';
import { demoPort, redirectsFor } from './redirects.mjs';
import { saveTrustChain, trustNote, trustPath } from './trust-chain.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const SSF_ROLES = [
  { scope: 'ssf.read', role: 'SSF_READ', group: 'ssf-read' },
  { scope: 'ssf.manage', role: 'SSF_MANAGE', group: 'ssf-manage' },
] as const;

export const GRANTS = ['authorization_code', 'refresh_token', 'client_credentials'] as const;

/** The realm setting that lets one browser hold several signed-in people. */
export const MULTIPLE_ACCOUNTS = { key: 'authn.multipleAccounts', value: true } as const;

export function usage(): string {
  return `Usage: node scripts/configure-iya-sts.ts [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's OpenID Connect configuration (default: demo/oidc.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: the origin of the configuration's metadataUrl, or $IYA_STS_URL)
  --public-url    Replace the origin of the file's redirect URIs with this URL, and keep their paths
                  (default: unset; $PUBLIC_URL). Without it, a loopback redirect follows the
                  running demo's PORT, then $PORT. A non-loopback redirect is left as written.
  --test-user     The test user to create (default: oidc-demo-user). Its password is
                  $OIDC_DEMO_USER_PASSWORD, or one is generated and written to
                  demo/generated/<user>.password (mode 0600); only that path is printed. With that
                  variable set, an existing user's password is replaced.
  --no-test-user  Do not create a test user.
  --dry-run       Print what would be done, and send nothing. Does not write a secret.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.`;
}

export interface Args {
  config: string;
  idp: string;
  publicUrl: string;
  /** Set when --public-url or PUBLIC_URL was given. The default does not count. */
  publicUrlGiven: boolean;
  testUser: string;
  dryRun: boolean;
  help: boolean;
  /** Set when --idp was given, so the file's metadata URL does not replace it. */
  idpGiven: boolean;
}

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Args {
  const out: Args = {
    config: resolve(repoRoot, 'demo/oidc.json'),
    idp: (env.IYA_STS_URL || '').replace(/\/+$/, ''),
    publicUrl: (env.PUBLIC_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    publicUrlGiven: Boolean(env.PUBLIC_URL),
    testUser: 'oidc-demo-user',
    dryRun: false,
    help: false,
    idpGiven: Boolean(env.IYA_STS_URL),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value\n${usage()}`);
      return v;
    };
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--config') out.config = resolve(value());
    else if (arg === '--idp') {
      out.idp = value().replace(/\/+$/, '');
      out.idpGiven = true;
    } else if (arg === '--public-url') {
      out.publicUrl = value().replace(/\/+$/, '');
      out.publicUrlGiven = true;
    }
    else if (arg === '--test-user') out.testUser = value().trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else if (arg === '--dry-run') out.dryRun = true;
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  if (out.idp) {
    const u = new URL(out.idp);
    if (u.protocol !== 'https:') throw new Error(`--idp must be https, not ${out.idp}`);
  }
  if (!out.publicUrl) throw new Error('--public-url is empty');
  return out;
}

export interface DemoFiles {
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  scopes: string[];
  tokenEndpointAuthMethod: string;
  metadataUrl: string;
  secretFile: string;
  tlsCa?: string;
  ssfTransmitter?: string;
}

/** The files and the client the configuration names. Registration then applies {@link redirectsFor}. */
export function filesOf(configPath: string, publicUrl: string): DemoFiles {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as {
    client_id?: string;
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
    redirect_uri?: string;
    postLogoutRedirectUri?: string;
    post_logout_redirect_uri?: string;
    scopes?: string | string[];
    tokenEndpointAuthMethod?: string;
    metadataUrl?: string;
    tlsCa?: string;
    signals?: unknown;
    ssf?: { transmitter?: string };
  };
  const base = dirname(configPath);
  const at = (p: string) => (isAbsolute(p) ? p : resolve(base, p));
  const clientId = String(raw.clientId ?? raw.client_id ?? '').trim();
  const metadataUrl = String(raw.metadataUrl ?? '').trim();
  if (!clientId) throw new Error(`${configPath} has no client_id`);
  if (!metadataUrl) throw new Error(`${configPath} has no metadataUrl`);
  const method = String(raw.tokenEndpointAuthMethod ?? 'client_secret_basic');
  if (method === 'none') throw new Error(`${configPath} asks for a public client; this demo registers a confidential one`);
  const secretRaw = String(raw.clientSecret ?? '');
  if (!secretRaw.startsWith('file:')) throw new Error(`${configPath}'s clientSecret must be a file: path so this script can write it`);
  const scopes = Array.isArray(raw.scopes)
    ? raw.scopes.map((s) => String(s).trim()).filter(Boolean)
    : String(raw.scopes ?? '').trim().split(/\s+/).filter(Boolean);
  if (!scopes.includes('openid')) throw new Error(`${configPath}'s scopes must include openid`);
  if (raw.signals !== undefined && typeof raw.signals !== 'boolean') throw new Error(`${configPath}: signals must be true or false`);
  const signals = raw.signals !== false;
  const used = signals ? scopes : scopes.filter((scope) => scope !== 'ssf.read' && scope !== 'ssf.manage');
  const origin = publicUrl.endsWith('/') ? publicUrl : `${publicUrl}/`;
  const redirectUri = String(raw.redirectUri ?? raw.redirect_uri ?? '').trim() || new URL('callback', origin).href;
  const postLogoutRedirectUri = String(raw.postLogoutRedirectUri ?? raw.post_logout_redirect_uri ?? '').trim() || new URL('./', origin).href;
  const tlsCa = trustPath(raw.tlsCa, base);
  return {
    clientId,
    redirectUri,
    postLogoutRedirectUri,
    scopes: used,
    tokenEndpointAuthMethod: method,
    metadataUrl,
    secretFile: at(secretRaw.slice(5)),
    ...(tlsCa ? { tlsCa } : {}),
    ...(signals && raw.ssf?.transmitter ? { ssfTransmitter: raw.ssf.transmitter.replace(/\/+$/, '') } : {}),
  };
}

/** The realm's base and the origin a token is minted at. */
export function realmOf(idp: string): { origin: string; base: string } {
  const u = new URL(idp);
  if (u.protocol !== 'https:') throw new Error(`the provider must be https, not ${idp}`);
  const path = u.pathname.replace(/\/+$/, '');
  if (path && !/^\/realm\/[^/]+$/.test(path)) throw new Error(`--idp must be iya-sts's base URL or a realm's (/realm/<id>), not ${idp}`);
  return { origin: u.origin, base: `${u.origin}${path}` };
}

export interface Call {
  method: string;
  path: string;
  body?: unknown;
  why: string;
  /** create: only when the application is new. exists: only when it already is. always: either way. */
  when: 'create' | 'exists' | 'always';
}

/**
 * The application's fields, without its client secret. The secret joins the create call only as it
 * is sent (main()), so the plan, which --dry-run prints and errors quote, never holds it.
 */
export function applicationFields(files: DemoFiles): Record<string, unknown> {
  return {
    oauthClientId: files.clientId,
    oauthRedirectUri: [files.redirectUri],
    oauthPostLogoutRedirectUri: [files.postLogoutRedirectUri],
    oauthResponseType: ['code'],
    oauthGrantType: [...GRANTS],
    oauthAllowedScope: files.scopes,
    oauthTokenEndpointAuthMethod: files.tokenEndpointAuthMethod,
  };
}

/** What a product-mode realm's attribute policy requires of every person. */
export function userAttributes(username: string): Record<string, string> {
  return {
    cn: `OIDC Demo ${username}`,
    givenName: 'OIDC',
    sn: 'Demo',
    displayName: `OIDC Demo ${username}`,
    mail: `${username}@oidc-demo.test`,
  };
}

/**
 * The management API calls. None holds the client secret: main() adds it to the create call as it
 * sends it. The calls marked `exists` add the same values, so a re-run does not rotate it.
 */
export function planFor(files: DemoFiles, base: string, testUser: string): Call[] {
  const fields = applicationFields(files);
  const calls: Call[] = [
    {
      method: 'POST', path: `${base}/admin-api/applications/create`, when: 'create',
      why: `register ${files.clientId}`,
      body: {
        identifier: files.clientId,
        name: 'oidc-caep-risc-nodejs demo',
        protocols: ['oauth2', 'oidc'],
        fields,
      },
    },
  ];
  for (const protocol of ['oauth2', 'oidc']) {
    calls.push({
      method: 'POST', path: `${base}/admin-api/applications/add`, when: 'exists',
      why: `declare protocol ${protocol}`,
      body: { application: files.clientId, attribute: 'appAllowedProtocol', value: protocol },
    });
  }
  for (const [attribute, raw] of Object.entries(fields)) {
    const values = Array.isArray(raw) ? raw.map(String) : [String(raw)];
    for (const value of values) {
      calls.push({
        method: 'POST', path: `${base}/admin-api/applications/add`, when: 'exists',
        why: `add ${attribute}`,
        body: { application: files.clientId, attribute, value },
      });
    }
  }
  calls.push({
    method: 'POST', path: `${base}/admin-api/config/set`, when: 'always',
    why: 'let one browser hold several accounts',
    body: MULTIPLE_ACCOUNTS,
  });
  for (const { scope, role } of SSF_ROLES) {
    if (!files.scopes.includes(scope)) continue;
    calls.push({
      method: 'POST', path: `${base}/admin-api/roles/add-member`, when: 'always',
      why: `hold ${role}, which authorizes ${scope}`,
      body: { role, kind: 'application', member: files.clientId },
    });
  }
  if (testUser) {
    calls.push({
      method: 'POST', path: `${base}/admin-api/users/create`, when: 'always',
      why: `create the test user ${testUser}`,
      body: { username: testUser, invent: false, credential: 'generate', attributes: userAttributes(testUser) },
    });
    for (const { scope, group } of SSF_ROLES) {
      if (!files.scopes.includes(scope)) continue;
      calls.push({
        method: 'POST', path: `${base}/admin-api/groups/add-member`, when: 'always',
        why: `put ${testUser} in ${group}`,
        body: { group, member: testUser },
      });
    }
  }
  return calls;
}

async function json(url: string, ca: string | undefined, init: { method?: string; headers?: Record<string, string>; body?: string }) {
  const answer = await send(url, init, ca ? { ca } : {}, 'config');
  let body: Record<string, unknown> = {};
  try {
    body = answer.body ? JSON.parse(answer.body) as Record<string, unknown> : {};
  } catch {
    throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status} with non-JSON: ${answer.body.slice(0, 300)}`);
  }
  if (answer.status === 401 || answer.status === 403) throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status}: ${JSON.stringify(body).slice(0, 300)}`);
  return { status: answer.status, body };
}

const errorsOf = (body: Record<string, unknown>) => ([] as unknown[]).concat(body.errors ?? []).map(String);

async function mintAdminToken(base: string, ca: string | undefined, secret: string): Promise<string> {
  const form = new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read admin:write', resource: `${base}/admin-api` });
  const reply = await json(`${base}/oauth2/token`, ca, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}`,
    },
    body: form.toString(),
  });
  if (reply.status !== 200 || typeof reply.body.access_token !== 'string') {
    throw new Error(`the token endpoint answered ${reply.status} ${JSON.stringify(reply.body).slice(0, 300)}`);
  }
  return reply.body.access_token;
}

/**
 * The file a generated test-user password is written to: <directory>/<username>.password. It is
 * computed apart from the password, so the path the script prints is not derived from one.
 */
export function generatedFile(directory: string, username: string): string {
  if (!username || /[/\\]/.test(username) || username === '.' || username === '..') {
    throw new Error(`${JSON.stringify(username)} cannot name a file`);
  }
  return resolve(directory, `${username}.password`);
}

/**
 * Writes text to path, readable and writable by its owner only. The file is CREATED 0600, so it is
 * never readable by anyone else, not even for a moment; an existing file is narrowed to 0600 before
 * it is rewritten. A generated password goes here and is never printed: a password does not belong
 * in a log. demo/generated never enters an image except the IdP trust chain (.dockerignore).
 */
export function writePrivate(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, 'w', 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

/** PORT from the running oidc-demo container, when compose has one. Docker being absent is not an error. */
export function containerPort(cwd = repoRoot): string | undefined {
  try {
    const id = execFileSync('docker', ['compose', 'ps', '-q', 'oidc-demo'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim().split('\n')[0];
    if (!id) return undefined;
    const env = execFileSync('docker', ['inspect', '-f', '{{range .Config.Env}}{{println .}}{{end}}', id], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return env.split('\n').find((line) => line.startsWith('PORT='))?.slice('PORT='.length);
  } catch {
    return undefined;
  }
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const files = filesOf(args.config, args.publicUrl);
  const port = demoPort(process.env.PORT, containerPort());
  const redirects = redirectsFor(files.redirectUri, files.postLogoutRedirectUri, {
    publicUrl: args.publicUrl, publicUrlGiven: args.publicUrlGiven, port,
  });
  files.redirectUri = redirects.redirectUri;
  files.postLogoutRedirectUri = redirects.postLogoutRedirectUri;
  const idp = args.idp || new URL(files.metadataUrl).origin;
  const { origin, base } = realmOf(idp);

  const onDisk = existsSync(files.secretFile) ? readFileSync(files.secretFile, 'utf8').trim() : '';
  if (args.dryRun) {
    if (files.tlsCa) console.log(`# would save ${origin}'s listener CA trust chain to ${files.tlsCa}`);
    if (!onDisk) console.log(`# would write a new client secret (mode 0600) to the file clientSecret names in ${args.config}`);
    else console.log(`# would keep the client secret in the file clientSecret names in ${args.config}`);
    // The plan holds no client secret, so nothing printed here is derived from one.
    console.log('# the create call also sends the client secret as oauthClientSecret (not shown)');
    for (const call of planFor(files, base, args.testUser)) {
      console.log(`${call.method} ${call.path}  # ${call.when}: ${call.why}\n${JSON.stringify(call.body ?? {}, null, 2)}`);
    }
    return;
  }

  let ca: string | undefined;
  if (files.tlsCa) {
    const chain = await saveTrustChain(origin, files.tlsCa);
    ca = chain.pem;
    console.log(`Saved ${origin}'s listener CA trust chain (${chain.count} certificate(s)) to ${files.tlsCa}`);
    console.log(`  ${trustNote(chain)}`);
    console.log(`  trust anchor ${chain.anchor.subject.replace(/\n/g, ', ')}`);
    console.log(`  sha256 ${chain.anchor.fingerprint256}`);
    console.log('  Compare the anchor with the Root CA on iya-sts\'s Server configuration, PKI page.');
    console.log('  The demo image build copies that trust chain in. Rebuild it after running this against another iya-sts.');
  }

  const adminSecret = process.env.ADMIN_API_CLIENT_SECRET || process.env.STS_ADMIN_API_CLIENT_SECRET || '';
  if (!adminSecret) throw new Error('neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.');
  const token = await mintAdminToken(base, ca, adminSecret);
  const api = (path: string, body: unknown, method = 'POST') => json(`${base}/admin-api${path}`, ca, {
    method,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });

  const minted = !onDisk;
  const secret = onDisk || randomBytes(32).toString('base64url');
  const plan = planFor(files, base, args.testUser);
  const create = plan.find((call) => call.when === 'create')?.body as { fields: Record<string, unknown> };
  // The secret joins a copy of the create body as it is sent; the plan never holds it.
  const created = await api('/applications/create', { ...create, fields: { ...create.fields, oauthClientSecret: secret } });
  let fresh = false;
  if (created.body.ok) {
    fresh = true;
    if (minted) writePrivate(files.secretFile, `${secret}\n`);
    console.log(`Registered ${files.clientId}. Its client secret is in the file clientSecret names in ${args.config} (mode 0600).`);
  } else if (errorsOf(created.body).some((e) => /already in this registry/i.test(e))) {
    if (minted) {
      throw new Error(`${files.clientId} already exists, and the file clientSecret names in ${args.config} is missing. This script does not rotate the client secret. Restore that file, or set a new secret on the application, then re-run.`);
    }
    console.log(`${files.clientId} is already registered; adding the demo's values. The client secret is unchanged.`);
    for (const call of plan.filter((one) => one.when === 'exists')) {
      const added = await api(call.path.slice(`${base}/admin-api`.length), call.body);
      const errors = errorsOf(added.body).join(' ');
      if (!added.body.ok && !/already/i.test(errors)) throw new Error(`${call.why}: refused: ${JSON.stringify(added.body).slice(0, 400)}`);
    }
  } else {
    throw new Error(`iya-sts refused to create ${files.clientId}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }

  for (const call of plan.filter((one) => one.when === 'always' && (one.path.endsWith('/config/set') || one.path.endsWith('/roles/add-member')))) {
    const answered = await api(call.path.slice(`${base}/admin-api`.length), call.body);
    const errors = errorsOf(answered.body).join(' ');
    if (!answered.body.ok && !/already/i.test(errors)) throw new Error(`${call.why}: refused: ${JSON.stringify(answered.body).slice(0, 400)}`);
    if (!answered.body.ok) console.log(`  ${call.why}: already so`);
  }
  if (fresh) console.log('authn.multipleAccounts is on, and the Shared Signals roles were granted for the scopes in the file.');

  if (args.testUser) {
    const found = await api(`/users?user=${encodeURIComponent(args.testUser)}`, undefined, 'GET');
    const password = process.env.OIDC_DEMO_USER_PASSWORD || '';
    if (found.body.known === true && password) {
      const set = await api('/users/set-password', { user: args.testUser, password, passwordConfirm: password });
      if (!set.body.ok) throw new Error(`setting ${args.testUser}'s password was refused: ${JSON.stringify(set.body).slice(0, 300)}`);
      console.log(`User ${args.testUser} already exists; its password is now OIDC_DEMO_USER_PASSWORD.`);
    } else if (found.body.known === true) {
      console.log(`User ${args.testUser} already exists; its password is unchanged (set OIDC_DEMO_USER_PASSWORD to replace it).`);
    } else {
      const body = password
        ? { username: args.testUser, invent: false, credential: 'password', password, passwordConfirm: password, attributes: userAttributes(args.testUser) }
        : { username: args.testUser, invent: false, credential: 'generate', attributes: userAttributes(args.testUser) };
      const made = await api('/users/create', body);
      if (!made.body.ok) throw new Error(`creating ${args.testUser} was refused: ${JSON.stringify(made.body).slice(0, 300)}`);
      console.log(`Created user ${args.testUser}.`);
      if (made.body.password) {
        // rcbj: a generated password is never printed. It goes to a file only its owner can read,
        // and only the path, which does not depend on the password, is printed.
        const saved = generatedFile(resolve(dirname(resolve(args.config)), 'generated'), args.testUser);
        writePrivate(saved, `${String(made.body.password)}\n`);
        console.log(`Generated a password for ${args.testUser}; it is in ${saved} (readable by you only).`);
      }
    }
    for (const call of plan.filter((one) => one.path.endsWith('/groups/add-member'))) {
      const added = await api('/groups/add-member', call.body);
      if (!added.body.ok) throw new Error(`adding ${args.testUser} to a group was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
      const group = (call.body as { group?: string }).group;
      console.log(`${args.testUser} ${added.body.changed === false ? 'was already' : 'is now'} in ${group}.`);
    }
  }
  console.log(`client_id: ${files.clientId}`);
  console.log(`metadata:  ${files.metadataUrl}`);
  console.log(`redirect:  ${files.redirectUri}`);
  console.log(`auth:      ${files.tokenEndpointAuthMethod}`);
  console.log('Done. Start the demo with: docker compose up --build');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err: Error) => {
    console.error(err.message);
    process.exit(1);
  });
}
