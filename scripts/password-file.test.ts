// The install script never prints a generated test-user password: it writes it to
// demo/generated/<user>.password, created mode 0600, and prints only the path.
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generatedFile, writePrivate } from './configure-iya-sts.ts';

const here = dirname(fileURLToPath(import.meta.url));

describe('the generated password file', () => {
  it('is named for the user, in the directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'password-file-'));
    assert.equal(generatedFile(dir, 'demo-user'), resolve(dir, 'demo-user.password'));
  });

  it('is created 0600 from the start, whatever the umask', () => {
    const dir = mkdtempSync(join(tmpdir(), 'password-file-'));
    const target = generatedFile(join(dir, 'generated'), 'demo-user');
    const previous = process.umask(0);
    try {
      writePrivate(target, 's3cret-value\n');
    } finally {
      process.umask(previous);
    }
    assert.equal(statSync(target).mode & 0o777, 0o600);
    assert.equal(readFileSync(target, 'utf8'), 's3cret-value\n');
  });

  it('narrows an existing wider file to 0600', () => {
    const dir = mkdtempSync(join(tmpdir(), 'password-file-'));
    const existing = join(dir, 'demo-user.password');
    writeFileSync(existing, 'old\n');
    chmodSync(existing, 0o644);
    writePrivate(existing, 'new\n');
    assert.equal(statSync(existing).mode & 0o777, 0o600);
    assert.equal(readFileSync(existing, 'utf8'), 'new\n');
  });

  for (const username of ['', '.', '..', 'a/b', 'a\\b']) {
    it(`refuses ${JSON.stringify(username)} as a file name`, () => {
      assert.throws(() => generatedFile(tmpdir(), username));
    });
  }

  it('is never printed by the install script', () => {
    const source = readFileSync(join(here, 'configure-iya-sts.ts'), 'utf8');
    assert.ok(!source.includes('shown once'));
    for (const line of source.split('\n')) {
      if (line.includes('console.')) assert.ok(!/\.password\b/.test(line), line);
    }
  });
});
