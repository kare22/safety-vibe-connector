import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project, run, receiver } from './helpers.mjs';

const name = '@lottiefiles/creator-api-types';
const version = '0.1.1';
const download = `https://npm.pkg.github.com/download/${name}/${version}/245d3b271fc70c579103c858c48ff55a88a6261b`;
const formats = [
  ...[1, 2, 3].map(lockfileVersion => [`npm v${lockfileVersion}`, 'package-lock.json', (resolved, v = version) => JSON.stringify({
    lockfileVersion, ...(lockfileVersion === 1 ? { dependencies: { [name]: { version: v, resolved } } }
      : { packages: { ['node_modules/' + name]: { version: v, resolved } } }),
  })]),
  ['Yarn v1', 'yarn.lock', (resolved, v = version) => `# yarn lockfile v1\n\n"${name}@^0.1.0":\n  version "${v}"\n  resolved ${JSON.stringify(resolved)}\n`],
  ...['5.4', '6.0', '9.0'].map(lockfileVersion => [`pnpm v${lockfileVersion}`, 'pnpm-lock.yaml', (resolved, v = version) =>
    `lockfileVersion: '${lockfileVersion}'\npackages:\n  '${lockfileVersion === '9.0' ? name + '@' + v : '/' + name + (lockfileVersion === '6.0' ? '@' : '/') + v}':\n    resolution: {integrity: sha512-fixture, tarball: '${resolved}'}\n`]),
];
const routes = [
  ['GitHub Packages scoped download', download],
  ['GitLab project npm tarball', `https://gitlab.com/api/v4/projects/123/packages/npm/${name}/-/${name}-${version}.tgz`],
  ['GitLab instance npm tarball', `https://gitlab.com/api/v4/packages/npm/${name}/-/${name}-${version}.tgz`],
  ['GitLab project opaque route', 'https://gitlab.com/api/v4/projects/123/packages/npm/opaque-id'],
  ['GitLab instance opaque route', 'https://gitlab.com/api/v4/packages/npm/opaque-id'],
];
for (const [format, file, lock] of formats) {
  for (const [label, resolved] of routes) test(`${format} retains ${label} and reports successfully`, async t => {
    const root = project(t); const server = await receiver(t);
    writeFileSync(join(root, file), lock(resolved));
    const report = buildReport(root, {}, {});
    const expected = [{ ecosystem: 'npm', name, version }];
    assert.deepEqual(report.packages, expected);
    assert.equal(Object.hasOwn(report, 'incomplete'), false);
    const result = await run(root, ['setup', '--no-hook', '--claim-token', 'a'.repeat(24)], server);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(server.hits.length, 1);
    assert.deepEqual(server.hits[0].packages, expected);
    assert.equal(Object.hasOwn(server.hits[0], 'incomplete'), false);
  });
  for (const [label, resolved, v = version] of [
    ['non URL', 'not-a-url'],
    ['missing version', download, ''],
    ['download version mismatch', download.replace('/0.1.1/', '/0.1.2/')],
    ['npm tarball version mismatch', 'https://registry.npmjs.org/pkg/-/pkg-0.1.2.tgz'],
    ['download version mismatch with an opaque suffix', download.replace('/0.1.1/', '/0.1.2/').replace(/[^/]+$/, 'opaque-download-id')],
  ]) test(`${format} refuses ${label} before reporting`, async t => {
    const root = project(t); const server = await receiver(t);
    writeFileSync(join(root, file), lock(resolved, v));
    assert.equal(buildReport(root, {}, {}).incomplete, true);
    const result = await run(root, ['setup', '--no-hook'], server);
    assert.equal(result.code, 1, result.stderr);
    assert.equal(server.hits.length, 0);
  });
  test(`${format} excludes archives on source hosts`, t => {
    const root = project(t);
    for (const resolved of ['https://github.com/owner/repo/archive/revision.tar.gz', 'https://codeload.github.com/owner/repo/tar.gz/revision',
      'https://gitlab.com/group/repo/-/archive/main/repo-main.tar.gz', 'https://bitbucket.org/owner/repo/get/main.tar.gz']) {
      writeFileSync(join(root, file), lock(resolved));
      const report = buildReport(root, {}, {});
      assert.deepEqual(report.packages, [], resolved);
      assert.equal(report.incomplete, undefined, resolved);
    }
  });
  test(`${format} refuses non-canonical archive paths on public registry hosts`, t => {
    const root = project(t);
    for (const resolved of ['https://registry.npmjs.org/archive/revision.tgz', 'https://npm.pkg.github.com/owner/repo/archive/revision.tar.gz']) {
      writeFileSync(join(root, file), lock(resolved));
      const report = buildReport(root, {}, {});
      assert.deepEqual(report.packages, []);
      assert.equal(report.incomplete, true);
    }
  });
}
