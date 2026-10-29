import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromPackageLock, readPackages, buildReport } from '../lib.mjs';
import { project, json, run, receiver } from './helpers.mjs';

for (const tag of ['latest', 'next', 'beta', 'release-2026']) test('resolves direct and transitive tag ' + tag, t => {
  const root = project(t, { dependencies: { lodash: tag } });
  const lock = { packages: { '': { dependencies: { lodash: tag } },
    'node_modules/lodash': { version: '4.17.20', dependencies: { child: tag } },
    'node_modules/child': { version: '1.2.3' } } };
  json(root, 'package-lock.json', lock);
  assert.deepEqual(fromPackageLock(lock).map(p => p.name), ['lodash', 'child']);
  assert.equal(readPackages(root).packages[0].version, '4.17.20');
  assert.equal(buildReport(root, {}, {}).incomplete, undefined);
});

test('distinguishes incomplete registry rows from intentional exclusions and empty locks', t => {
  const root = project(t);
  json(root, 'package-lock.json', { packages: { 'node_modules/broken': {} } });
  assert.equal(readPackages(root).incomplete, true);
  assert.equal(buildReport(root, {}, {}).incomplete, true);
  json(root, 'package-lock.json', { packages: { '': { dependencies: { missing: 'latest' } } } });
  assert.equal(readPackages(root).incomplete, true);
  json(root, 'package-lock.json', { packages: { '': {}, 'node_modules/local': { link: true } } });
  assert.deepEqual(readPackages(root), { packages: [], source: 'package-lock.json' });
  json(root, 'package-lock.json', { packages: {} });
  assert.deepEqual(readPackages(root), { packages: [], source: 'package-lock.json' });
});

for (const [file, text] of [
  ['yarn.lock', '# yarn lockfile v1\n\nbroken@latest:\n  version "not-resolved"\n'],
  ['pnpm-lock.yaml', "lockfileVersion: '9.0'\npackages:\n  broken@latest:\n    resolution: {integrity: sha512-test}\n"],
  ['bun.lock', '{"packages":{"broken":["broken@latest","",{},"sha512-test"]}}'],
]) test('marks unparsed registry rows incomplete: ' + file, t => {
  const root = project(t); writeFileSync(join(root, file), text);
  assert.equal(buildReport(root, {}, {}).incomplete, true);
});

test('incomplete local preview is marked and real reports cannot clear receiver state', async t => {
  const root = project(t); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: { 'node_modules/broken': {} } });
  const preview = await run(root, ['inventory', '--json']);
  assert.equal(JSON.parse(preview.stdout).incomplete, true);
  for (const command of ['setup', 'scan']) {
    const result = await run(root, [command, '--json', '--no-hook'], server);
    assert.equal(result.code, command === 'setup' ? 1 : 0);
    assert.equal(result.stdout, ''); assert.match(result.stderr, /incomplete.*nothing sent/i);
  }
  assert.equal(server.hits.length, 0);
});

test('summary previews disclose incomplete coverage', async t => {
  const root = project(t);
  json(root, 'package-lock.json', { packages: { 'node_modules/broken': {} } });
  const result = await run(root, ['inventory', '--summary']);
  assert.equal(result.code, 0); assert.match(result.stdout + result.stderr, /incomplete/i);
});
