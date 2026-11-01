// The setup script's plan, offline: a confidential client, the same scopes as oidc-caep-client, no secret rotation.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { GRANTS, MULTIPLE_ACCOUNTS, SSF_ROLES, filesOf, parseArgs, planFor, realmOf, userAttributes } from './configure-iya-sts.ts';

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
    assert.deepEqual(files.scopes, 'openid profile email offline_access ssf.read ssf.manage'.split(' '));
  });

  it('registers a confidential client and does not send the secret again when the application exists', () => {
    const files = filesOf(config, 'http://localhost:3000');
    const plan = planFor(files, 'https://localhost:8081', 'oidc-demo-user', 's3cret');
    const create = plan.find((call) => call.when === 'create');
    assert.ok(create);
    assert.match(create.path, /\/admin-api\/applications\/create$/);
    const body = create.body as { identifier: string; name: string; protocols: string[]; fields: Record<string, unknown> };
    assert.equal(body.identifier, 'oidc-caep-risc-demo');
    assert.equal(body.name, 'oidc-caep-risc-nodejs demo');
    assert.deepEqual(body.protocols, ['oauth2', 'oidc']);
    assert.equal(body.fields.oauthClientSecret, 's3cret');
    assert.deepEqual(body.fields.oauthGrantType, [...GRANTS]);
    assert.deepEqual(body.fields.oauthResponseType, ['code']);
    assert.equal(body.fields.oauthTokenEndpointAuthMethod, 'client_secret_basic');
    assert.deepEqual(body.fields.oauthAllowedScope, files.scopes);
    assert.equal(body.fields.oauthRedirectUri && (body.fields.oauthRedirectUri as string[])[0], 'http://localhost:3000/callback');
    assert.equal('appCorsOrigin' in body.fields, false);
    const again = plan.filter((call) => call.when === 'exists').map((call) => JSON.stringify(call.body));
    assert.ok(again.length > 0);
    assert.ok(again.every((text) => !text.includes('s3cret') && !text.includes('oauthClientSecret')));
    assert.deepEqual(plan.find((call) => call.path.endsWith('/config/set'))?.body, MULTIPLE_ACCOUNTS);
    const roles = plan.filter((call) => call.path.endsWith('/roles/add-member')).map((call) => (call.body as { role: string }).role);
    assert.deepEqual(roles, SSF_ROLES.map((role) => role.role));
    const user = plan.find((call) => call.path.endsWith('/users/create'));
    assert.deepEqual((user?.body as { username: string }).username, 'oidc-demo-user');
    assert.deepEqual((user?.body as { attributes: Record<string, string> }).attributes, userAttributes('oidc-demo-user'));
    const groups = plan.filter((call) => call.path.endsWith('/groups/add-member')).map((call) => (call.body as { group: string }).group);
    assert.deepEqual(groups, ['ssf-read', 'ssf-manage']);
    assert.equal(planFor(files, 'https://localhost:8081', '', 's3cret').some((call) => call.path.endsWith('/users/create')), false);
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
    assert.equal(args.testUser, '');
    assert.equal(args.dryRun, true);
    assert.equal(args.config.endsWith('/demo/oidc.json'), true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });
});
