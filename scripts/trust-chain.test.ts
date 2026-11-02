// tlsCa end to end, offline: the install script's saveTrustChain writes iya-sts's whole listener CA
// trust chain (leaf, TLS Issuing CA, Intermediate, Root) to the file demo/oidc.json's tlsCa names,
// and the library trusts an HTTPS provider through that file as it is.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { discoverProvider, readConfigFile } from '../packages/oidc-caep-risc-nodejs/src/index.ts';
import { acceptFirstUse, saveTrustChain, trustPath } from './trust-chain.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** A four-certificate chain shaped like iya-sts's: Root, Intermediate, TLS Issuing CA, leaf. */
function makeChain(work: string) {
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  const ext = join(work, 'ext.cnf');
  writeFileSync(ext, [
    '[ca]',
    'basicConstraints = critical, CA:TRUE',
    'keyUsage = critical, keyCertSign, cRLSign',
    '[leaf]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = IP:127.0.0.1, DNS:localhost',
    '[elsewhere]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = DNS:elsewhere.example',
    '',
  ].join('\n'));
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=sts Root CA',
    '-keyout', join(work, 'root.key'), '-out', join(work, 'root.pem'));
  const issue = (name: string, subject: string, issuer: string, section: string) => {
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', subject,
      '-keyout', join(work, `${name}.key`), '-out', join(work, `${name}.csr`));
    openssl('x509', '-req', '-in', join(work, `${name}.csr`), '-days', '1', '-set_serial', String(Date.now()),
      '-CA', join(work, `${issuer}.pem`), '-CAkey', join(work, `${issuer}.key`),
      '-extfile', ext, '-extensions', section, '-out', join(work, `${name}.pem`));
  };
  issue('intermediate', '/CN=sts Intermediate CA', 'root', 'ca');
  issue('issuing', '/CN=sts TLS Issuing CA', 'intermediate', 'ca');
  issue('leaf', '/CN=localhost', 'issuing', 'leaf');
  // The same chain, a leaf for another name: the trust file must not be enough on its own.
  issue('elsewhere', '/CN=elsewhere.example', 'issuing', 'elsewhere');
  const pem = (name: string) => readFileSync(join(work, `${name}.pem`), 'utf8').trim();
  return {
    key: readFileSync(join(work, 'leaf.key')),
    elsewhereKey: readFileSync(join(work, 'elsewhere.key')),
    elsewhere: `${pem('elsewhere')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    presented: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    published: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n${pem('root')}\n`,
    root: new X509Certificate(pem('root')),
  };
}

describe('the iya-sts trust chain in tlsCa', () => {
  const work = mkdtempSync(join(tmpdir(), 'oidc-tlsca-'));
  const chain = makeChain(work);
  let server: https.Server;
  let elsewhere: https.Server;
  let origin = '';
  let elsewherePort = 0;

  before(async () => {
    server = https.createServer({ key: chain.key, cert: chain.presented }, (req, res) => {
      if (req.url === '/tls/server-certificate') {
        res.setHeader('content-type', 'text/plain');
        res.end(chain.published);
        return;
      }
      if (req.url === '/.well-known/openid-configuration') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          issuer: origin,
          authorization_endpoint: `${origin}/oauth2/authorize`,
          token_endpoint: `${origin}/oauth2/token`,
          jwks_uri: `${origin}/oauth2/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
        }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
    origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    elsewhere = https.createServer({ key: chain.elsewhereKey, cert: chain.elsewhere }, (req, res) => {
      res.setHeader('content-type', 'text/plain');
      res.end(req.url === '/tls/server-certificate' ? chain.published : '');
    });
    await new Promise<void>((done) => elsewhere.listen(0, '127.0.0.1', () => done()));
    elsewherePort = (elsewhere.address() as AddressInfo).port;
  });

  after(async () => {
    await new Promise<void>((done) => server.close(() => done()));
    await new Promise<void>((done) => elsewhere.close(() => done()));
  });

  // demo/oidc.json as shipped, in a scratch demo directory, so tlsCa resolves as it does in the image.
  const demo = join(work, 'demo');
  const config = join(demo, 'oidc.json');

  it('the install script writes the whole chain to the file tlsCa names', async () => {
    mkdirSync(demo, { recursive: true });
    copyFileSync(join(repoRoot, 'demo/oidc.json'), config);
    const raw = JSON.parse(readFileSync(config, 'utf8')) as { tlsCa: string };
    assert.equal(raw.tlsCa, 'generated/idp-ca.pem');
    const dest = trustPath(raw.tlsCa, demo);
    assert.equal(dest, join(demo, 'generated/idp-ca.pem'));
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.verified, false, 'no file yet: trust on first use');
    assert.equal(saved.count, 4);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    const written = readFileSync(dest!, 'utf8').match(BLOCK) ?? [];
    const expected = chain.published.match(BLOCK) ?? [];
    assert.equal(written.length, 4);
    assert.deepEqual(written.map((pem) => new X509Certificate(pem).fingerprint256), expected.map((pem) => new X509Certificate(pem).fingerprint256));
    assert.equal(new X509Certificate(written[3]!).subject, 'CN=sts Root CA');
  });

  it('a later refresh verifies the server against the chain the file already holds', async () => {
    const dest = join(demo, 'generated/idp-ca.pem');
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.verified, true);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
  });

  it('a held chain that verifies the server is not given up for a host name the leaf does not carry', async () => {
    const dest = join(work, 'held-elsewhere.pem');
    copyFileSync(join(demo, 'generated/idp-ca.pem'), dest);
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, dest), /altnames|Hostname/);
    assert.equal(readFileSync(dest, 'utf8'), readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
  });

  it('a held chain from another CA (a restarted development iya-sts) is replaced on first use', async () => {
    const other = mkdtempSync(join(tmpdir(), 'oidc-tlsca-other-'));
    const stale = makeChain(other);
    const dest = join(work, 'stale.pem');
    writeFileSync(dest, stale.published);
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.verified, false);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    assert.notEqual(saved.anchor.fingerprint256, stale.root.fingerprint256);
  });

  it('first use checks the host name, the presented leaf, and every link of the chain', async () => {
    const certs = (chain.published.match(BLOCK) ?? []).map((pem) => new X509Certificate(pem));
    const [leaf, issuing, intermediate, root] = certs as [X509Certificate, X509Certificate, X509Certificate, X509Certificate];
    acceptFirstUse('127.0.0.1', { certs, leaf });
    assert.throws(() => acceptFirstUse('elsewhere.example', { certs, leaf }), /altnames|Hostname/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs, leaf: issuing }), /handshake presented/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [leaf, intermediate, root], leaf }), /not signed/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [], leaf }), /no certificates/);
    // Without a held chain, a server whose leaf does not name the host is refused too.
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, join(work, 'none.pem')));
  });

  it('the library trusts the provider through that file, and not without it', async () => {
    const doc = JSON.parse(readFileSync(config, 'utf8')) as Record<string, unknown>;
    doc.metadataUrl = `${origin}/.well-known/openid-configuration`;
    writeFileSync(join(demo, 'generated/client-secret'), 's3cret\n');
    writeFileSync(config, JSON.stringify(doc));
    const resolved = readConfigFile(config);
    assert.equal(resolved.tlsCa, readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
    const metadata = await discoverProvider(resolved.metadataUrl!, { ca: resolved.tlsCa! });
    assert.equal(metadata.issuer, origin);
    await assert.rejects(discoverProvider(resolved.metadataUrl!));
  });
});
