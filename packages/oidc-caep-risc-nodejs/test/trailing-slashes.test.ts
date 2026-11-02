// Trailing slashes are trimmed in linear time (CodeQL js/polynomial-redos). `replace(/\/+$/, '')`
// retries at every slash of a run that is not at the end of the string, so a configured URL with a
// long run of slashes followed by any other character took seconds; the loop takes microseconds.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { issuerFromMetadataUrl, resolveConfig, SignalsReceiver, wellKnownUrls } from '../src/index.ts';
import { trimTrailingSlashes } from '../src/discovery.ts';

const RUN = '/'.repeat(100_000);
const BUDGET_MS = 500;

function timed<T>(what: string, fn: () => T): T {
  const started = performance.now();
  const result = fn();
  const took = performance.now() - started;
  assert.ok(took < BUDGET_MS, `${what} took ${Math.round(took)} ms`);
  return result;
}

describe('trailing slashes', () => {
  it('trims them and nothing else', () => {
    assert.equal(trimTrailingSlashes('https://sts/'), 'https://sts');
    assert.equal(trimTrailingSlashes('https://sts///'), 'https://sts');
    assert.equal(trimTrailingSlashes('https://sts//a'), 'https://sts//a');
    assert.equal(trimTrailingSlashes('///'), '');
    assert.equal(trimTrailingSlashes(''), '');
  });

  it('trims a long run of slashes that is not at the end in linear time', () => {
    const value = `https://sts${RUN}x`;
    assert.equal(timed('trimTrailingSlashes', () => trimTrailingSlashes(value)), value);
    assert.equal(timed('a run at the end', () => trimTrailingSlashes(`https://sts${RUN}`)), 'https://sts');
  });

  it('builds the signals receiver from such a transmitter in linear time', () => {
    timed('new SignalsReceiver', () => new SignalsReceiver({
      transmitter: `https://sts${RUN}x`,
      onEndSessions: () => {},
      log: { info() {}, warn() {}, error() {} },
    }));
  });

  it('resolves a configuration with such a transmitter in linear time', () => {
    const config = timed('resolveConfig', () => resolveConfig({
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      clientId: 'c',
      clientSecret: 's',
      redirectUri: 'http://localhost:3000/callback',
      ssf: { transmitter: `https://sts${RUN}x` },
    }, '.'));
    assert.equal(config.ssf?.transmitter, `https://sts${RUN}x`);
    assert.equal(resolveConfig({
      metadataUrl: 'https://localhost:8081/.well-known/openid-configuration',
      clientId: 'c',
      clientSecret: 's',
      redirectUri: 'http://localhost:3000/callback',
      ssf: { transmitter: 'https://sts/ssf//' },
    }, '.').ssf?.transmitter, 'https://sts/ssf');
  });

  it('builds well-known URLs from such an issuer path in linear time', () => {
    const urls = timed('wellKnownUrls', () => wellKnownUrls(`https://sts${RUN}x`, 'ssf-configuration'));
    assert.equal(urls[0], `https://sts/.well-known/ssf-configuration${RUN}x`);
    assert.deepEqual(wellKnownUrls('https://sts/realm/a/', 'ssf-configuration'), [
      'https://sts/.well-known/ssf-configuration/realm/a',
      'https://sts/realm/a/.well-known/ssf-configuration',
    ]);
    const issuer = timed('issuerFromMetadataUrl', () =>
      issuerFromMetadataUrl(`https://sts/a${RUN}x${RUN}/.well-known/openid-configuration`));
    assert.equal(issuer, `https://sts/a${RUN}x`);
  });
});
