import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project, run, receiver } from './helpers.mjs';

const version = '1.2.3';
const snapshot = root => Object.fromEntries(readdirSync(root).sort().map(file => [file, readFileSync(join(root, file), 'utf8')]));
const formats = [
  ...[1, 2, 3].map(lockfileVersion => [`npm v${lockfileVersion}`, 'package-lock.json', (name, resolved, alias) => JSON.stringify({
    lockfileVersion, ...(lockfileVersion === 1 ? { dependencies: { [alias || name]: { version: alias ? `npm:${name}@${version}` : version, resolved } } }
      : { packages: { ['node_modules/' + (alias || name)]: { name, version, resolved } } }),
  })]),
  ['Yarn v1', 'yarn.lock', (name, resolved, alias) => `# yarn lockfile v1\n\n"${alias ? alias + '@npm:' + name : name}@latest":\n  version "${version}"\n  resolved ${JSON.stringify(resolved)}\n`],
  ...['5.4', '6.0', '9.0'].map(v => [`pnpm v${v}`, 'pnpm-lock.yaml', (name, resolved) =>
    `lockfileVersion: '${v}'\npackages:\n  '${v === '9.0' ? name + '@' + version : '/' + name + (v === '6.0' ? '@' : '/') + version}':\n    resolution: {integrity: sha512-fixture, tarball: '${resolved}'}\n`]),
];

for (const [format, file, lock] of formats) {
  for (const [label, resolved] of [
    ['malformed version', 'https://registry.npmjs.org/lodash/-/lodash-not-a-version.tgz'],
    ['missing version', 'https://registry.npmjs.org/lodash/-/lodash.tgz'],
    ['different version', 'https://registry.npmjs.org/lodash/-/lodash-1.2.4.tgz'],
    ['different package', 'https://registry.npmjs.org/other/-/other-1.2.3.tgz'],
  ]) test(`${format} refuses canonical tarballs with ${label} without requests or config changes`, async t => {
    const root = project(t); const server = await receiver(t);
    writeFileSync(join(root, file), lock('lodash', resolved));
    const before = snapshot(root);
    const report = buildReport(root, {}, {});
    assert.equal(report.incomplete, true);
    assert.deepEqual(report.packages, []);
    for (const command of ['setup', 'scan']) {
      const result = await run(root, [command, '--json', '--no-hook'], server);
      assert.equal(result.code, command === 'setup' ? 1 : 0, result.stderr);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /incomplete.*nothing sent/i);
      assert.deepEqual(snapshot(root), before);
    }
    assert.equal(server.hits.length, 0);
  });
  if (!format.startsWith('pnpm')) for (const name of ['real-name', '@acme/real-name']) {
    test(`${format} validates tarball identity against the alias target ${name}`, t => {
      const root = project(t);
      const resolved = `https://registry.npmjs.org/${name}/-/real-name-${version}.tgz`;
      writeFileSync(join(root, file), lock(name, resolved, 'local-alias'));
      const report = buildReport(root, {}, {});
      assert.equal(report.incomplete, undefined);
      assert.deepEqual(report.packages, [{ ecosystem: 'npm', name, version }]);
      writeFileSync(join(root, file), lock(name, resolved.replace('/real-name-', '/local-alias-'), 'local-alias'));
      assert.equal(buildReport(root, {}, {}).incomplete, true);
    });
  }
  for (const name of ['archive', 'tarball', 'zipball', '@acme/archive', '@acme/tarball', '@acme/zipball']) {
    test(`${format} retains registry package ${name} through reporting`, async t => {
      const root = project(t); const server = await receiver(t);
      const basename = name.split('/').at(-1);
      for (const resolved of [
        `https://registry.npmjs.org/${name}/-/${basename}-${version}.tgz`,
        `https://nexus.example/repository/archive/${name}/-/${basename}-${version}.tgz`,
        `https://mirror.example/archive/npm/${name}/-/${basename}-${version}.tgz`,
        `https://npm.pkg.github.com/download/${name}/${version}/abc123`,
      ]) {
        writeFileSync(join(root, file), lock(name, resolved));
        const report = buildReport(root, {}, {});
        const expected = [{ ecosystem: 'npm', name, version }];
        assert.deepEqual(report.packages, expected, resolved);
        assert.equal(report.incomplete, undefined, resolved);
        const result = await run(root, ['setup', '--no-hook'], server);
        assert.equal(result.code, 0, result.stderr);
        assert.deepEqual(server.hits.at(-1).packages, expected);
      }
      assert.equal(server.hits.length, 4);
    });
  }
}
