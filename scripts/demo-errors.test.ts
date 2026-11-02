// The demo never shows an exception's text. Each case starts demo/server.ts with a configuration
// that makes the library or the provider fail with a message carrying a secret-looking marker, and
// asserts the marker reaches the demo's log (so the failure happened, with that text) and no response
// body: not the 500 page, not the sign-in page, not a refused sign-in, not /live-status.
import assert from 'node:assert/strict';
import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(here, '../demo/server.ts');
const MARKER = 'sk_live_LEAKME_9f3c2a7b1d';

const children: ChildProcess[] = [];
after(() => {
  for (const child of children) child.kill('SIGKILL');
});

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const probe = createServer();
    probe.once('error', fail);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => ok(typeof address === 'object' && address ? address.port : 0));
    });
  });
}

const metadata = {
  issuer: 'https://idp.test',
  authorization_endpoint: 'https://idp.test/authorize',
  token_endpoint: 'https://idp.test/token',
  jwks_uri: 'https://idp.test/jwks',
  response_types_supported: ['code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
  code_challenge_methods_supported: ['S256'],
};

async function startDemo(config: Record<string, unknown>, env: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'demo-errors-'));
  writeFileSync(join(dir, 'client-secret'), 'test-client-secret\n');
  writeFileSync(join(dir, 'metadata.json'), JSON.stringify(metadata));
  const port = await freePort();
  const configFile = join(dir, 'oidc.json');
  writeFileSync(configFile, JSON.stringify({ redirectUri: `http://127.0.0.1:${port}/callback`, ...config }));
  const child = spawn(process.execPath, [SERVER], {
    env: { PATH: process.env.PATH ?? '', PORT: String(port), OIDC_CONFIG: configFile, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let log = '';
  child.stdout!.on('data', (d) => { log += d; });
  child.stderr!.on('data', (d) => { log += d; });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) break;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { base, dir, log: () => log };
}


async function eventually(check: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 100 && !check(); i++) await new Promise((r) => setTimeout(r, 100));
  assert.ok(check(), what);
}

describe('the demo error pages', () => {
  it('show no exception text when the relying party cannot be built', async () => {
    // The library's config error quotes the metadata file's path, and so the marker.
    const demo = await startDemo(
      { client_id: 'demo', clientSecret: 'file:client-secret' },
      { OIDC_METADATA_FILE: `/nonexistent/${MARKER}/metadata.json` },
    );
    const home = await fetch(`${demo.base}/`);
    const homeBody = await home.text();
    assert.equal(home.status, 200);
    assert.match(homeBody, /not configured yet/);

    const login = await fetch(`${demo.base}/login`, { redirect: 'manual' });
    const loginBody = await login.text();
    assert.equal(login.status, 500);
    assert.match(loginBody, /Something went wrong/);

    const callback = await fetch(`${demo.base}/callback?state=x&code=y`, { redirect: 'manual' });
    const callbackBody = await callback.text();
    assert.equal(callback.status, 500);

    const status = await (await fetch(`${demo.base}/live-status`)).text();

    await eventually(() => demo.log().includes(MARKER), 'the error, with its message, is logged');
    assert.match(demo.log(), /request failed: OidcError: could not read metadata/);
    for (const body of [homeBody, loginBody, callbackBody, status]) {
      assert.ok(!body.includes(MARKER), `a response carried the error's text: ${body}`);
      assert.ok(!body.includes('nonexistent'), `a response carried the error's text: ${body}`);
      assert.ok(!body.includes('ENOENT'), `a response carried the error's text: ${body}`);
    }
  });

  it('shows a fixed label for a refused sign-in, never the provider error_description', async () => {
    const demo = await startDemo({ client_id: 'demo', clientSecret: 'file:client-secret', metadataFile: 'metadata.json', signals: false });
    const login = await fetch(`${demo.base}/login`, { redirect: 'manual' });
    assert.equal(login.status, 302);
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
    const txn = /oidc_txn=[^;]+/.exec(login.headers.get('set-cookie') ?? '')![0];
    const query = new URLSearchParams({ state, error: 'access_denied', error_description: `the key ${MARKER} was refused` });
    const refused = await fetch(`${demo.base}/callback?${query}`, { redirect: 'manual', headers: { cookie: txn } });
    const body = await refused.text();
    assert.equal(refused.status, 400);
    assert.match(body, /The identity provider refused the sign-in, or did not answer as expected\./);
    assert.ok(!body.includes(MARKER), `the refusal page carried the provider's error_description: ${body}`);
    assert.ok(!body.includes('access_denied'), `the refusal page carried the provider's error: ${body}`);
    await eventually(() => demo.log().includes(MARKER), 'the refusal, with its description, is logged');
    assert.match(demo.log(), /sign-in refused \(protocol\)/);

    // A callback this browser did not start is the library's validation code, and its label.
    const stray = await (await fetch(`${demo.base}/callback?state=${MARKER}&code=x`, { redirect: 'manual' })).text();
    assert.match(stray, /The sign-in response did not pass this application&#39;s checks\./);
    assert.ok(!stray.includes(MARKER));
  });

  it('keeps a receiver failure off the events tab and /live-status', async () => {
    const closed = await freePort();
    const demo = await startDemo({
      client_id: 'demo', clientSecret: 'file:client-secret', metadataFile: 'metadata.json',
      ssf: { transmitter: `https://127.0.0.1:${closed}/${MARKER}` },
    });
    await fetch(`${demo.base}/`);
    let status: { receiver?: string } = {};
    let raw = '';
    await eventually(() => {
      void fetch(`${demo.base}/live-status`).then((r) => r.text()).then((t) => {
        raw = t;
        status = JSON.parse(t) as { receiver?: string };
      }, () => {});
      return String(status.receiver ?? '').startsWith('not running');
    }, 'the receiver reports that it is not running');
    assert.equal(status.receiver, "not running (the receiver did not start; see the demo's log)");
    assert.ok(!raw.includes(MARKER));
    assert.match(demo.log(), /ssf: the receiver did not start: /);
  });
});
