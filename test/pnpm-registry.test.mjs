import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project, run, receiver } from './helpers.mjs';

for (const generation of ['5.4', '6.0', '9.0']) {
  test(`pnpm ${generation} retains registry names containing a source-host word`, async t => {
    const root = project(t); const server = await receiver(t);
    const names = ['github-slugger', 'my-github-helper', '@scope/github-utils', '@github/registry-package'];
    const heading = (name, version) => (generation === '9.0' ? '' : '/') + name + (generation === '5.4' ? '/' : '@') + version;
    writeFileSync(join(root, 'pnpm-lock.yaml'), `lockfileVersion: '${generation}'\npackages:\n` + names.map(name =>
      `  '${heading(name, '2.0.0')}':\n    resolution: {integrity: sha512-fixture}\n`).join('') +
      "  'github.com/owner/source/revision':\n    resolution: {type: git, repo: https://github.com/owner/source, commit: fixture}\n" +
      "  'source@github:owner/source':\n    resolution: {integrity: sha512-fixture}\n");
    const report = buildReport(root, {}, {});
    assert.equal(report.incomplete, undefined);
    assert.deepEqual(report.packages.map(p => p.name), names);
    const result = await run(root, ['setup', '--no-hook'], server);
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(server.hits[0].packages, report.packages);
  });
}

for (const resolution of [
  '{integrity: sha512-fixture, tarball: https://registry.npmjs.org/github-slugger/-/github-slugger-2.0.0.tgz}',
  '\n      integrity: sha512-fixture\n      tarball: https://registry.npmjs.org/github-slugger/-/github-slugger-2.0.0.tgz',
]) test('pnpm classifies an explicit registry tarball from resolution fields', t => {
  const root = project(t);
  writeFileSync(join(root, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'\npackages:\n  github-slugger@2.0.0:\n    resolution: ${resolution}\n`);
  const report = buildReport(root, {}, {});
  assert.equal(report.incomplete, undefined);
  assert.deepEqual(report.packages, [{ ecosystem: 'npm', name: 'github-slugger', version: '2.0.0' }]);
});

test('pnpm does not hide a screened version behind a source-host substring', async t => {
  const root = project(t); const server = await receiver(t);
  writeFileSync(join(root, 'pnpm-lock.yaml'), `packages:\n  pkg@1.2.3-github_pat_${'a1'.repeat(20)}:\n    resolution: {integrity: sha512-fixture}\n`);
  assert.equal(buildReport(root, {}, {}).incomplete, true);
  const result = await run(root, ['setup', '--no-hook'], server);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /screened value/i);
  assert.equal(server.hits.length, 0);
});

test('pnpm marks unknown resolution fields incomplete instead of excluding the package', t => {
  const root = project(t);
  for (const resolution of ['{integrity: sha512-fixture, tarball: not-a-url}', '{type: unknown}', '{repo: not-a-url}']) {
    writeFileSync(join(root, 'pnpm-lock.yaml'), `packages:\n  pkg@1.2.3:\n    resolution: ${resolution}\n`);
    assert.equal(buildReport(root, {}, {}).incomplete, true, resolution);
  }
});
