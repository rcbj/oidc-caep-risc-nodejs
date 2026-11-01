// The Shared Signals receiver against a stub transmitter. The stub signs with node:crypto; the
// receiver verifies with its own code. Events are matched to local sessions by subject and sid.

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { EVENT, OidcError, SignalsReceiver, subjectOf, type SignalEvent } from '../src/index.ts';
import { verifyCompactJws } from '../src/ssf/jws.ts';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };

function jws(payload: object, key = privateKey, header: object = { alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' }): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
}

interface Stub {
  url: string;
  queue: Map<string, string>;
  acked: string[];
  errs: Record<string, unknown>;
  created: number;
  authorization: string;
  close(): Promise<void>;
}

async function startTransmitter(): Promise<Stub> {
  const queue = new Map<string, string>();
  const acked: string[] = [];
  const errs: Record<string, unknown> = {};
  const streams: Record<string, unknown>[] = [];
  let created = 0;
  let base = '';
  let authorization = '';
  const server = http.createServer((req, res) => {
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => {
      authorization = String(req.headers.authorization ?? '');
      if (authorization !== 'Bearer app-token' && req.url !== '/.well-known/ssf-configuration' && !req.url?.startsWith('/jwks')) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_token' }));
        return;
      }
      const out = (status: number, body?: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(body === undefined ? '' : JSON.stringify(body));
      };
      const url = new URL(req.url ?? '/', base);
      if (url.pathname === '/.well-known/ssf-configuration') {
        return out(200, {
          issuer: base, jwks_uri: `${base}/jwks`, configuration_endpoint: `${base}/ssf/stream`,
          verification_endpoint: `${base}/ssf/verify`, delivery_methods_supported: ['urn:ietf:rfc:8936'],
        });
      }
      if (url.pathname === '/jwks') return out(200, { keys: [jwk] });
      if (url.pathname === '/ssf/stream' && req.method === 'GET') return out(200, streams);
      if (url.pathname === '/ssf/stream' && req.method === 'POST') {
        const body = JSON.parse(text) as { delivery: { method: string }; events_requested: string[] };
        created += 1;
        const stream = {
          stream_id: `s${created}`, iss: base, aud: 'my-app',
          delivery: { method: body.delivery.method, endpoint_url: `${base}/ssf/poll/s${created}` },
          events_requested: body.events_requested, events_delivered: body.events_requested,
        };
        streams.push(stream);
        return out(201, stream);
      }
      if (url.pathname === '/ssf/verify') return out(204);
      if (url.pathname.startsWith('/ssf/poll/')) {
        const body = JSON.parse(text || '{}') as { ack?: string[]; setErrs?: Record<string, unknown> };
        for (const jti of body.ack ?? []) {
          acked.push(jti);
          queue.delete(jti);
        }
        Object.assign(errs, body.setErrs ?? {});
        for (const jti of Object.keys(body.setErrs ?? {})) queue.delete(jti);
        return out(200, { sets: Object.fromEntries(queue), moreAvailable: false });
      }
      return out(404, { error: 'not_found' });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url: base, queue, acked, errs,
    get created() { return created; },
    get authorization() { return authorization; },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

function deliver(stub: Stub, type: string, subId: object, extra: object = {}, opts: { key?: typeof privateKey; aud?: string; iss?: string } = {}): string {
  const jti = randomUUID();
  stub.queue.set(jti, jws({
    iss: opts.iss ?? stub.url, aud: opts.aud ?? 'my-app', jti, iat: Math.floor(Date.now() / 1000),
    sub_id: subId, events: { [type]: { event_timestamp: 1, ...extra } },
  }, opts.key));
  return jti;
}

const session = (localId: string, person: string, sid: string) => ({
  localId, person: `urn:uuid:${person}`, email: `${person}@example.com`, idpSession: sid,
});

describe('the Shared Signals receiver', { concurrency: 1 }, () => {
  let stub: Stub;
  before(async () => { stub = await startTransmitter(); });
  after(async () => { await stub.close(); });

  it('verifies a SET against the JWKS and refuses another key', () => {
    assert.deepEqual(verifyCompactJws(jws({ a: 1 }), [jwk]).payload, { a: 1 });
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, other.privateKey), [jwk]), /does not verify/);
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, privateKey, { alg: 'RS256', kid: 'nope' }), [jwk]), /kid nope/);
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, privateKey, { alg: 'none' }), [jwk]), /does not verify/);
  });

  it('reads the same subject forms the browser client does', () => {
    assert.equal(EVENT.sessionRevoked, 'https://schemas.openid.net/secevent/caep/event-type/session-revoked');
    assert.equal(EVENT.credentialCompromise, 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise');
    assert.deepEqual(subjectOf({
      format: 'complex',
      user: { format: 'iss_sub', iss: 'https://i', sub: 'urn:uuid:a' },
      session: { format: 'opaque', id: 'S1' },
    }, 'https://i'), { person: 'urn:uuid:a', idpSession: 'S1' });
    assert.deepEqual(subjectOf({ format: 'iss_sub', iss: 'https://other', sub: 'urn:uuid:a' }, 'https://i'), {});
    assert.deepEqual(subjectOf({ format: 'email', email: 'A@x.com' }, 'https://i'), { email: 'A@x.com' });
  });

  it('polls with the application token, ends only the named session, and acknowledges', async () => {
    const ended: string[][] = [];
    const seen: SignalEvent[] = [];
    const receiver = new SignalsReceiver({
      transmitter: stub.url,
      headers: () => ({ authorization: 'Bearer app-token' }),
      onEndSessions: (ids) => { ended.push(ids); },
      pollIntervalMs: 60_000,
      log: { info() {}, warn() {}, error() {} },
    });
    receiver.on('*', (event) => { seen.push(event); });
    await receiver.start();
    receiver.stop();
    assert.equal(stub.created, 1);
    assert.equal(stub.authorization, 'Bearer app-token');
    assert.equal(receiver.stream?.stream_id, 's1');

    await receiver.track(session('L-a1', 'alice', 'IDP-A1'));
    await receiver.track(session('L-a2', 'alice', 'IDP-A2'));
    await receiver.track(session('L-b1', 'bob', 'IDP-B1'));

    const revoked = deliver(stub, EVENT.sessionRevoked, {
      format: 'complex',
      user: { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:alice' },
      session: { format: 'opaque', id: 'IDP-A1' },
    });
    deliver(stub, EVENT.credentialChange, { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:bob' }, { credential_type: 'password' });
    await receiver.pollOnce();
    assert.deepEqual(ended, [['L-a1']]);
    assert.equal(seen.length, 2);
    assert.equal(seen[0]?.ended, true);
    assert.equal(seen[1]?.type, EVENT.credentialChange);
    assert.equal(seen[1]?.ended, false);

    await receiver.pollOnce();
    assert.deepEqual(stub.acked, [revoked, ...stub.acked.filter((id) => id !== revoked)]);
    const bad = deliver(stub, EVENT.accountDisabled, { format: 'email', email: 'alice@example.com' }, {}, { key: other.privateKey });
    await receiver.pollOnce();
    await receiver.pollOnce();
    assert.equal(stub.errs[bad] && (stub.errs[bad] as { err: string }).err, 'invalid_key');
    await receiver.verify('abc');
    receiver.stop();
  });
});

void OidcError;
