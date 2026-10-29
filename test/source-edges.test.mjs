import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromPackageLock, fromYarnLock, fromPnpmLock, fromBunLock, buildReport } from '../lib.mjs';
import { assertAccounted } from './source-accounting.mjs';
import { project } from './helpers.mjs';

const registry = { name: 'lodash', version: '4.17.20' };
const resolved = 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz';
const source = 'git+https://code.example/lodash.git';
for (const nested of [false, true]) test(`npm source edges cannot exclude a separate registry installation (${nested ? 'nested' : 'workspace'})`, () => {
  const parent = nested ? 'node_modules/consumer' : 'packages/consumer';
  const packages = {
    '': { dependencies: { lodash: '^4' } },
    'node_modules/lodash': { version: registry.version, resolved },
    [parent]: { version: '1.0.0', dependencies: { lodash: source } },
    [parent + '/node_modules/lodash']: { version: '4.17.21', resolved: source },
  };
  assertAccounted(fromPackageLock({ packages }), {
    rows: [registry, ...(nested ? [{ name: 'consumer', version: '1.0.0' }] : [])], incomplete: false,
    decisions: [{ key: 'node_modules/lodash', status: 'reported' }, ...(nested ? [{ key: parent, status: 'reported' }] : []),
      { key: parent + '/node_modules/lodash', status: 'excluded', reason: 'source protocol' }],
  });
});

for (const spec of ['latest', 'patch:lodash@npm%3A4.17.20#fix.patch']) test(`npm unresolved source edge cannot suppress a shared root registry installation: ${spec}`, () => {
  const rows = fromPackageLock({ packages: { '': { dependencies: { lodash: spec } },
    'node_modules/lodash': { version: registry.version, resolved }, 'packages/consumer': { dependencies: { lodash: source } } } });
  assertAccounted(rows, { rows: [registry], incomplete: false, decisions: [{ key: 'node_modules/lodash', status: 'reported' }] });
});

for (const name of ['lodash', '@acme/ui']) test(`npm v1 decodes actual alias version encoding for ${name}`, () => {
  const rows = fromPackageLock({ lockfileVersion: 1, dependencies: { compat: {
    version: `npm:${name}@1.2.3`, resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-1.2.3.tgz`,
  } } });
  assertAccounted(rows, { rows: [{ name, version: '1.2.3' }], incomplete: false, decisions: [{ key: 'node_modules/compat', status: 'reported' }] });
});

test('npm v1 parent requires and nested sources use installation paths', () => {
  assertAccounted(fromPackageLock({ dependencies: {
    lodash: { version: registry.version, resolved },
    consumer: { version: '1.0.0', requires: { lodash: 'https://private.example/renamed' }, dependencies: {
      lodash: { version: '1.2.3', resolved: 'https://private.example/renamed' },
    } },
  } }), { rows: [registry, { name: 'consumer', version: '1.0.0' }], incomplete: false, decisions: [
    { key: 'node_modules/lodash', status: 'reported' }, { key: 'node_modules/consumer', status: 'reported' },
    { key: 'node_modules/consumer/node_modules/lodash', status: 'excluded', reason: 'declared URL dependency' },
  ] });
});

for (const v of [1, 3]) test(`npm ${v} reads URL declarations from the selected manifest`, t => {
  const root = project(t, { dependencies: { lodash: 'https://registry.corp/lodash.tgz' } });
  const entry = { version: '4.17.20', resolved: 'https://registry.corp/lodash.tgz' };
  const lock = v === 1 ? { lockfileVersion: 1, dependencies: { lodash: entry } } : { lockfileVersion: 3, packages: { 'node_modules/lodash': entry } };
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify(lock));
  assert.deepEqual(buildReport(root, {}, {}).packages, []);
  assert.equal(buildReport(root, {}, {}).incomplete, undefined);
});

for (const name of ['lodash', '@acme/ui']) test(`Yarn v1 no-range npm alias identifies ${name}`, () => {
  assertAccounted(fromYarnLock(`"compat@npm:${name}":\n  version "1.2.3"\n`), { rows: [{ name, version: '1.2.3' }], incomplete: false,
    decisions: [{ key: 'compat@npm:' + name, status: 'reported' }] });
});

for (const berry of [false, true]) test(`Yarn ${berry ? 'Berry' : 'v1'} records separate registry and source selectors sharing a name`, () => {
  const text = berry ? `__metadata:\n  version: 8\n"lodash@npm:^4":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n"lodash@${source}":\n  version: 4.17.21\n  resolution: "lodash@${source}"\n`
    : `"lodash@^4":\n  version "4.17.20"\n  resolved "${resolved}"\n"lodash@${source}":\n  version "4.17.21"\n  resolved "${source}"\n`;
  assertAccounted(fromYarnLock(text), { rows: [registry], incomplete: false, decisions: [
    { key: berry ? 'lodash@npm:^4' : 'lodash@^4', status: 'reported' }, { key: 'lodash@' + source, status: 'excluded', reason: 'source protocol' },
  ] });
});

test('Yarn Berry retains patched registry identity', () => {
  const spec = '@acme/ui@patch:@acme/ui@npm%3A1.2.3#local.patch';
  assertAccounted(fromYarnLock(`__metadata:\n  version: 8\n"${spec}":\n  version: 1.2.3\n  resolution: "${spec}::version=1.2.3&hash=abc"\n`), {
    rows: [{ name: '@acme/ui', version: '1.2.3' }], incomplete: false, decisions: [{ key: spec, status: 'reported' }],
  });
});

for (const generation of ['5.4', '6.0', '9.0']) test(`pnpm ${generation} associates a URL specifier with its own version`, () => {
  const key = version => (generation === '9.0' ? '' : '/') + 'lodash' + (generation === '5.4' ? '/' : '@') + version;
  const imports = generation === '5.4'
    ? `specifiers:\n  lodash: https://registry.corp/custom.tgz\ndependencies:\n  lodash: 1.2.3\n`
    : `importers:\n  .:\n    dependencies:\n      lodash:\n        version: 1.2.3\n        specifier: https://registry.corp/custom.tgz\n  packages/other:\n    dependencies:\n      lodash:\n        specifier: ^4\n        version: 4.17.20\n`;
  const text = `lockfileVersion: '${generation}'\n${imports}packages:\n  '${key('1.2.3')}':\n    resolution: {integrity: sha512-fixture, tarball: https://registry.corp/custom.tgz}\n  '${key('4.17.20')}':\n    resolution: {integrity: sha512-fixture}\n`;
  assertAccounted(fromPnpmLock(text), { rows: [registry], incomplete: false, decisions: [
    { key: key('1.2.3'), status: 'excluded', reason: 'declared URL dependency' }, { key: key('4.17.20'), status: 'reported' },
  ] });
});

test('Bun declarations and parent metadata exclude only the source installation', () => {
  const json = { workspaces: { '': { dependencies: { lodash: '^4', consumer: '^1' } } }, packages: {
    lodash: ['lodash@4.17.20', '', {}, 'sha512-fixture'],
    consumer: ['consumer@1.0.0', '', { dependencies: { lodash: 'https://registry.corp/custom.tgz' } }, 'sha512-fixture'],
    'consumer/lodash': ['lodash@1.2.3', 'https://registry.corp/custom.tgz', {}, 'sha512-fixture'],
  } };
  assertAccounted(fromBunLock(JSON.stringify(json)), { rows: [registry, { name: 'consumer', version: '1.0.0' }], incomplete: false, decisions: [
    { key: 'lodash', status: 'reported' }, { key: 'consumer', status: 'reported' },
    { key: 'consumer/lodash', status: 'excluded', reason: 'declared URL dependency' },
  ] });
});

test('Bun workspace declarations remain local to their installations', () => {
  const json = { workspaces: { '': { dependencies: { lodash: '^4' } }, 'packages/local': { dependencies: { lodash: 'file:vendor' } } }, packages: {
    lodash: ['lodash@4.17.20', '', {}], local: ['local@workspace:packages/local'],
    'local/lodash': ['lodash@1.2.3', '', {}],
  } };
  assertAccounted(fromBunLock(JSON.stringify(json)), { rows: [registry], incomplete: false, decisions: [
    { key: 'lodash', status: 'reported' }, { key: 'local', status: 'excluded', reason: 'source protocol' },
    { key: 'local/lodash', status: 'excluded', reason: 'source protocol' },
  ] });
});

test('npm optional binaries for other platforms are accounted for in the lock inventory', () => {
  assertAccounted(fromPackageLock({ packages: { 'node_modules/binary': { version: '1.2.3', optional: true, os: ['darwin'], cpu: ['arm64'] } } }), {
    rows: [{ name: 'binary', version: '1.2.3' }], incomplete: false, decisions: [{ key: 'node_modules/binary', status: 'reported' }],
  });
});
