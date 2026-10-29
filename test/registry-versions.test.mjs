import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project, run, receiver } from './helpers.mjs';

const name = '@prisma/engines-version';
const prisma = '5.22.0-44.605197351a3c8bdd595af2d2a9bc3025bca48ea2';
const locks = [
  ['npm', 'package-lock.json', version => JSON.stringify({ packages: {
    ['node_modules/' + name]: { version, resolved: `https://registry.npmjs.org/${name}/-/engines-version-${version}.tgz` },
  } })],
  ['pnpm', 'pnpm-lock.yaml', version => `lockfileVersion: '9.0'\npackages:\n  '${name}@${version}':\n    resolution: {integrity: sha512-fixture}\n`],
  ['Yarn v1', 'yarn.lock', version => `# yarn lockfile v1\n\n"${name}@latest":\n  version "${version}"\n  resolved "https://registry.yarnpkg.com/${name}/-/engines-version-${version}.tgz"\n`],
  ['Yarn Berry', 'yarn.lock', version => `__metadata:\n  version: 8\n\n"${name}@npm:latest":\n  version: ${version}\n  resolution: "${name}@npm:${version}"\n`],
  ['Bun', 'bun.lock', version => JSON.stringify({ packages: { [name]: [`${name}@${version}`, '', {}, 'sha512-fixture'] } })],
];

for (const [format, file, lock] of locks) {
  for (const version of [prisma, '1.2.3-' + 'a1'.repeat(80), '1.2.3+build.' + 'b2'.repeat(80)]) {
    test(`${format} retains long registry semver identifiers`, async t => {
      const root = project(t); const server = await receiver(t);
      writeFileSync(join(root, file), lock(version));
      const report = buildReport(root, {}, {});
      assert.equal(report.incomplete, undefined);
      assert.deepEqual(report.packages, [{ ecosystem: 'npm', name, version }]);
      const result = await run(root, ['setup', '--no-hook'], server);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(server.hits.length, 1);
      assert.deepEqual(server.hits[0].packages, report.packages);
    });
  }
  for (const prefix of ['npm_', 'ghp_', 'sk_live_', 'sk-proj-']) {
    test(`${format} still screens provider prefixes inside semver`, async t => {
      const root = project(t); const version = '1.2.3-' + prefix + 'a1'.repeat(20);
      writeFileSync(join(root, file), lock(version));
      const result = await run(root, ['setup', '--no-hook']);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /screened value/i);
      assert.doesNotMatch(result.stderr, /repair the lockfile/i);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr.includes(version), false);
      const report = buildReport(root, {}, {});
      assert.equal(report.incomplete, true);
      assert.deepEqual(report.packages, []);
      assert.equal(Object.hasOwn(report, 'incompleteReasons'), false);
    });
  }
}

test('unidentified package sources have neutral local refusal guidance', async t => {
  const root = project(t);
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/broken': {} } }));
  const result = await run(root, ['setup', '--no-hook']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /package sources could not be identified/i);
  assert.match(result.stderr, /--dry-run/);
  assert.doesNotMatch(result.stderr, /malformed/i);
  assert.doesNotMatch(result.stderr, /screened value/i);
});
