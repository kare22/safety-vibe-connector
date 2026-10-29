import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project, json, run, receiver } from './helpers.mjs';

const formats = [
  ...[1, 2, 3].map(lockfileVersion => [`npm v${lockfileVersion}`, 'package-lock.json', resolved => JSON.stringify({
    lockfileVersion, ...(lockfileVersion === 1 ? { dependencies: { lodash: { version: '4.17.20', resolved } } }
      : { packages: { 'node_modules/lodash': { version: '4.17.20', resolved } } }),
  })]),
  ['Yarn v1', 'yarn.lock', resolved => `# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.20"\n  resolved ${JSON.stringify(resolved)}\n`],
];
const snapshot = root => Object.fromEntries(readdirSync(root).sort().map(file => [file, readFileSync(join(root, file), 'utf8')]));

for (const [format, file, lock] of formats) {
  for (const resolved of ['not-a-url', '', 'https://', 'custom:unknown']) {
    test(`${format} refuses malformed or unknown resolution metadata without changing a connection`, async t => {
      const root = project(t); const server = await receiver(t);
      writeFileSync(join(root, file), lock(resolved));
      json(root, '.safetyviberc.json', { site: '12345678-1234-1234-1234-123456789abc', url: 'https://notes.example', hook: false });
      json(root, '.safetyviberc.local.json', { key: 'svk_' + 'b'.repeat(32) });
      writeFileSync(join(root, '.gitignore'), '/.safetyviberc.local.json\n');
      const before = snapshot(root);
      for (const args of [['inventory', '--json'], ['setup', '--dry-run', '--json']]) {
        const result = await run(root, args, server);
        assert.equal(result.code, 0);
        assert.equal(JSON.parse(result.stdout).incomplete, true);
        assert.match(result.stderr, /package sources could not be identified/i);
      }
      for (const command of ['setup', 'scan']) {
        const result = await run(root, [command, '--json', '--no-hook'], server);
        assert.equal(result.code, command === 'setup' ? 1 : 0);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /incomplete.*nothing sent/i);
        assert.deepEqual(snapshot(root), before);
      }
      assert.equal(server.hits.length, 0);
    });
  }
  test(`${format} excludes positively identified non-registry resolutions`, t => {
    const root = project(t);
    for (const resolved of ['git+https://code.example/repo.git', 'file:../local', 'link:../local', 'workspace:*',
      'github:owner/repo', 'https://codeload.github.com/owner/repo/tar.gz/revision']) {
      writeFileSync(join(root, file), lock(resolved));
      const report = buildReport(root, {}, {});
      assert.equal(report.incomplete, undefined, resolved);
      assert.deepEqual(report.packages, [], resolved);
    }
  });
  test(`${format} distinguishes hosted package registries from source archives`, t => {
    const root = project(t);
    writeFileSync(join(root, file), lock('https://npm.pkg.github.com/lodash/-/lodash-4.17.20.tgz'));
    const report = buildReport(root, {}, {});
    assert.equal(report.incomplete, undefined);
    assert.deepEqual(report.packages, [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }]);
    writeFileSync(join(root, file), lock('https://npm.pkg.github.com/unknown-path.tgz'));
    assert.equal(buildReport(root, {}, {}).incomplete, true);
    assert.deepEqual(buildReport(root, {}, {}).packages, []);
  });
}

test('explicit npm source declarations remain excluded even with unknown transport metadata', t => {
  const root = project(t);
  json(root, 'package-lock.json', { packages: {
    '': { dependencies: { direct: 'https://downloads.example/dynamic' } },
    'node_modules/direct': { version: '1.2.3', resolved: 'https://downloads.example/dynamic' },
  } });
  assert.equal(buildReport(root, {}, {}).incomplete, undefined);
  assert.deepEqual(buildReport(root, {}, {}).packages, []);
});
