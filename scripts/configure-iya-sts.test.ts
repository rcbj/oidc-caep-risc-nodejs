// The setup script's plan, offline: a confidential client, the same scopes as oidc-caep-client, no secret rotation.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import type { ServerResponse } from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { GRANTS, MULTIPLE_ACCOUNTS, SSF_ROLES, filesOf, parseArgs, planFor, realmOf, userAttributes } from './configure-iya-sts.ts';
import { demoPort, redirectsFor } from './redirects.mjs';
import { fetchTrustChain, saveTrustChain, trustPath } from './trust-chain.mjs';

describe('configure-iya-sts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oidc-setup-'));
  const config = join(dir, 'oidc.json');
  writeFileSync(config, JSON.stringify({
    metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
    client_id: 'oidc-caep-risc-demo',
    clientSecret: 'file:generated/client-secret',
    redirectUri: 'http://localhost:3000/callback',
    postLogoutRedirectUri: 'http://localhost:3000/',
    scopes: 'openid profile email offline_access ssf.read ssf.manage',
    tokenEndpointAuthMethod: 'client_secret_basic',
    tlsCa: 'generated/idp-ca.pem',
    ssf: { transmitter: 'https://localhost:8081' },
  }));

  it('reads the file, and prefers its redirect URIs over --public-url', () => {
    const files = filesOf(config, 'http://other.example:9');
    assert.equal(files.clientId, 'oidc-caep-risc-demo');
    assert.equal(files.redirectUri, 'http://localhost:3000/callback');
    assert.equal(files.postLogoutRedirectUri, 'http://localhost:3000/');
    assert.equal(files.secretFile, join(dir, 'generated/client-secret'));
    assert.equal(files.tlsCa, join(dir, 'generated/idp-ca.pem'));
    assert.equal(trustPath('file:generated/idp-ca.pem', dir), join(dir, 'generated/idp-ca.pem'));
    assert.equal(trustPath('-----BEGIN CERTIFICATE-----\nY\n-----END CERTIFICATE-----', dir), undefined);
    assert.deepEqual(files.scopes, 'openid profile email offline_access ssf.read ssf.manage'.split(' '));
  });

  it('registers a confidential client, and no call in the plan holds the client secret', () => {
    const files = filesOf(config, 'http://localhost:3000');
    const plan = planFor(files, 'https://localhost:8081', 'oidc-demo-user');
    const create = plan.find((call) => call.when === 'create');
    assert.ok(create);
    assert.match(create.path, /\/admin-api\/applications\/create$/);
    const body = create.body as { identifier: string; name: string; protocols: string[]; fields: Record<string, unknown> };
    assert.equal(body.identifier, 'oidc-caep-risc-demo');
    assert.equal(body.name, 'oidc-caep-risc-nodejs demo');
    assert.deepEqual(body.protocols, ['oauth2', 'oidc']);
    assert.equal('oauthClientSecret' in body.fields, false);
    assert.deepEqual(body.fields.oauthGrantType, [...GRANTS]);
    assert.deepEqual(body.fields.oauthResponseType, ['code']);
    assert.equal(body.fields.oauthTokenEndpointAuthMethod, 'client_secret_basic');
    assert.deepEqual(body.fields.oauthAllowedScope, files.scopes);
    assert.equal(body.fields.oauthRedirectUri && (body.fields.oauthRedirectUri as string[])[0], 'http://localhost:3000/callback');
    assert.equal('appCorsOrigin' in body.fields, false);
    const again = plan.filter((call) => call.when === 'exists').map((call) => JSON.stringify(call.body));
    assert.ok(again.length > 0);
    assert.ok(plan.every((call) => !JSON.stringify(call.body).includes('oauthClientSecret')));
    assert.deepEqual(plan.find((call) => call.path.endsWith('/config/set'))?.body, MULTIPLE_ACCOUNTS);
    const roles = plan.filter((call) => call.path.endsWith('/roles/add-member')).map((call) => (call.body as { role: string }).role);
    assert.deepEqual(roles, SSF_ROLES.map((role) => role.role));
    const user = plan.find((call) => call.path.endsWith('/users/create'));
    assert.deepEqual((user?.body as { username: string }).username, 'oidc-demo-user');
    assert.deepEqual((user?.body as { attributes: Record<string, string> }).attributes, userAttributes('oidc-demo-user'));
    const groups = plan.filter((call) => call.path.endsWith('/groups/add-member')).map((call) => (call.body as { group: string }).group);
    assert.deepEqual(groups, ['ssf-read', 'ssf-manage']);
    assert.equal(planFor(files, 'https://localhost:8081', '').some((call) => call.path.endsWith('/users/create')), false);
  });

  it('does not register Shared Signals roles when signals is false', () => {
    const off = join(dir, 'off.json');
    writeFileSync(off, JSON.stringify({
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      client_id: 'oidc-caep-risc-demo',
      clientSecret: 'file:generated/client-secret',
      redirectUri: 'http://localhost:3000/callback',
      scopes: 'openid profile email offline_access ssf.read ssf.manage',
      signals: false,
      ssf: { transmitter: 'https://localhost:8081' },
    }));
    const files = filesOf(off, 'http://localhost:3000');
    assert.deepEqual(files.scopes, ['openid', 'profile', 'email', 'offline_access']);
    assert.equal(files.ssfTransmitter, undefined);
    const plan = planFor(files, 'https://localhost:8081', 'oidc-demo-user');
    assert.deepEqual(plan.filter((call) => call.path.endsWith('/roles/add-member')), []);
    assert.deepEqual(plan.filter((call) => call.path.endsWith('/groups/add-member')), []);
    const create = plan.find((call) => call.when === 'create');
    const allowed = (create?.body as { fields: { oauthAllowedScope: string[] } }).fields.oauthAllowedScope;
    assert.deepEqual(allowed, ['openid', 'profile', 'email', 'offline_access']);
    writeFileSync(off, JSON.stringify({
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      client_id: 'oidc-caep-risc-demo',
      clientSecret: 'file:generated/client-secret',
      redirectUri: 'http://localhost:3000/callback',
      scopes: 'openid ssf.read ssf.manage',
      signals: 'no',
    }));
    assert.throws(() => filesOf(off, 'http://localhost:3000'), /signals must be true or false/);
  });

  it('keeps a realm base and refuses any other path', () => {
    assert.deepEqual(realmOf('https://idp.test/realm/acme'), { origin: 'https://idp.test', base: 'https://idp.test/realm/acme' });
    assert.throws(() => realmOf('https://idp.test/oauth2'), /realm/);
    assert.throws(() => realmOf('http://idp.test'), /https/);
  });

  it('takes its options', () => {
    const args = parseArgs(['--idp', 'https://idp.test/', '--public-url', 'http://app.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(args.idp, 'https://idp.test');
    assert.equal(args.publicUrl, 'http://app.test');
    assert.equal(args.publicUrlGiven, true);
    assert.equal(parseArgs([], {}).publicUrlGiven, false);
    assert.equal(parseArgs([], { PUBLIC_URL: 'http://demo.test' }).publicUrlGiven, true);
    assert.equal(args.testUser, '');
    assert.equal(args.dryRun, true);
    assert.equal(args.config.endsWith('/demo/oidc.json'), true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });

  it('registers a loopback redirect on the port the demo listens on', () => {
    const file = { redirectUri: 'http://localhost:3000/callback', postLogoutRedirectUri: 'http://localhost:3000/' };
    const moved = redirectsFor(file.redirectUri, file.postLogoutRedirectUri, { publicUrlGiven: false, port: 3001 });
    assert.equal(moved.redirectUri, 'http://localhost:3001/callback');
    assert.equal(moved.postLogoutRedirectUri, 'http://localhost:3001/');
    const published = redirectsFor('https://app.example/callback', 'https://app.example/', { publicUrlGiven: false, port: 3001 });
    assert.equal(published.redirectUri, 'https://app.example/callback');
    const explicit = redirectsFor(file.redirectUri, file.postLogoutRedirectUri, { publicUrl: 'http://app.test:9', publicUrlGiven: true, port: 3001 });
    assert.equal(explicit.redirectUri, 'http://app.test:9/callback');
    assert.equal(explicit.postLogoutRedirectUri, 'http://app.test:9/');
    assert.equal(demoPort('3000', '3001'), 3001);
    assert.equal(demoPort('3001', ''), 3001);
    assert.equal(demoPort('', undefined), undefined);
    assert.equal(demoPort('nope', undefined), undefined);
    const files = filesOf(config, 'http://localhost:3000');
    const redirects = redirectsFor(files.redirectUri, files.postLogoutRedirectUri, { publicUrlGiven: false, port: 3001 });
    files.redirectUri = redirects.redirectUri;
    files.postLogoutRedirectUri = redirects.postLogoutRedirectUri;
    const body = planFor(files, 'https://localhost:8081', '').find((call) => call.when === 'create')?.body as { fields: { oauthRedirectUri: string[]; oauthPostLogoutRedirectUri: string[] } };
    assert.deepEqual(body.fields.oauthRedirectUri, ['http://localhost:3001/callback']);
    assert.deepEqual(body.fields.oauthPostLogoutRedirectUri, ['http://localhost:3001/']);
  });

  it('saves the published listener CA trust chain, and the handshake when that document is absent', async () => {
    const work = mkdtempSync(join(tmpdir(), 'oidc-chain-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(work, 'key.pem'), '-out', join(work, 'cert.pem'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' });
    const certificatePem = readFileSync(join(work, 'cert.pem'), 'utf8');
    const key = readFileSync(join(work, 'key.pem'));
    const leaf = new X509Certificate(certificatePem);
    const listen = (handler: (url: string | undefined, res: ServerResponse) => void) => new Promise<https.Server>((resolve) => {
      const server = https.createServer({ key, cert: certificatePem }, (req, res) => handler(req.url, res));
      server.listen(0, '127.0.0.1', () => resolve(server));
    });
    const close = (server: https.Server) => new Promise<void>((resolve) => server.close(() => resolve()));

    const published = await listen((_url, res) => {
      res.setHeader('content-type', 'text/plain');
      res.end(`${certificatePem}${certificatePem}`);
    });
    try {
      const origin = `https://127.0.0.1:${(published.address() as AddressInfo).port}`;
      const chain = await fetchTrustChain(origin);
      assert.equal(chain.count, 2);
      assert.equal(chain.anchor.fingerprint256, leaf.fingerprint256);
      const dest = join(work, 'idp-ca.pem');
      writeFileSync(dest, 'stale\n');
      const saved = await saveTrustChain(origin, dest);
      assert.equal(saved.count, 2);
      assert.match(readFileSync(dest, 'utf8'), /BEGIN CERTIFICATE/);
      assert.doesNotMatch(readFileSync(dest, 'utf8'), /stale/);
    } finally {
      await close(published);
    }

    const handshakeOnly = await listen((_url, res) => {
      res.statusCode = 404;
      res.end('no');
    });
    try {
      const origin = `https://127.0.0.1:${(handshakeOnly.address() as AddressInfo).port}`;
      const chain = await fetchTrustChain(origin);
      assert.equal(chain.count, 1);
      assert.equal(chain.anchor.fingerprint256, leaf.fingerprint256);
    } finally {
      await close(handshakeOnly);
    }
  });
});
