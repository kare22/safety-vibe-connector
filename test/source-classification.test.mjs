import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as lib from '../lib.mjs';
import { assertAccounted, assertFixtureAccounted } from './source-accounting.mjs';
import { project, run, receiver } from './helpers.mjs';

const corpus = JSON.parse(readFileSync(new URL('./fixtures/source-corpus.json', import.meta.url), 'utf8'));
for (const fixture of corpus) test(`source corpus ${fixture.round}: ${fixture.label}`, () => {
  assertFixtureAccounted(lib[fixture.parser](...fixture.args), fixture);
});

const row = (name, version = '1.2.3') => ({ name, version });
const formats = [
  ...[1, 2, 3].map(v => ({ label: `npm ${v}`, parser: lib.fromPackageLock, file: 'package-lock.json',
    lock: (name, version, url, spec = '^1') => v === 1
      ? { lockfileVersion: 1, dependencies: { [name]: { version, resolved: url } } }
      : { lockfileVersion: v, packages: { '': { dependencies: { [name]: spec } }, ['node_modules/' + name]: { version, resolved: url } } },
    key: name => 'node_modules/' + name })),
  { label: 'Yarn v1', parser: lib.fromYarnLock, file: 'yarn.lock', lock: (name, version, url, spec = '^1') =>
    `# yarn lockfile v1\n\n"${name}@${spec}":\n  version "${version}"\n  resolved "${url}"\n`, key: name => name + '@^1' },
  ...['5.4', '6.0', '9.0'].map(v => ({ label: `pnpm ${v}`, parser: lib.fromPnpmLock, file: 'pnpm-lock.yaml',
    lock: (name, version, url) => `lockfileVersion: '${v}'\npackages:\n  '${v === '9.0' ? '' : '/'}${name}${v === '5.4' ? '/' : '@'}${version}':\n    resolution: {integrity: sha512-fixture, tarball: '${url}'}\n`,
    key: (name, version) => (v === '9.0' ? '' : '/') + name + (v === '5.4' ? '/' : '@') + version })),
  { label: 'Bun', parser: lib.fromBunLock, file: 'bun.lock', lock: (name, version, url) =>
    JSON.stringify({ packages: { [name]: [`${name}@${version}`, url, {}, 'sha512-fixture'] } }), key: name => name },
];
const retained = [
  ['Artifactory scoped filename', '@acme/ui', 'https://acme.jfrog.io/artifactory/api/npm/npm-virtual/@acme/ui/-/@acme/ui-1.2.3.tgz'],
  ['self-hosted GitLab scoped filename', '@acme/ui', 'https://gitlab.corp/api/v4/projects/123/packages/npm/@acme/ui/-/@acme/ui-1.2.3.tgz'],
  ['FontAwesome version directory', '@fortawesome/pro-solid-svg-icons', 'https://npm.fontawesome.com/@fortawesome/pro-solid-svg-icons/-/1.2.3/pro-solid-svg-icons-1.2.3.tgz'],
  ['renamed private artifact', '@acme/ui', 'https://registry.corp/@acme/ui/-/acme-ui-1.2.3.tgz'],
  ['different package on a mirror', 'lodash', 'https://nexus.example/repository/archive/lodash/-/other-1.2.3.tgz'],
  ['malformed filename version on GitLab', 'lodash', 'https://gitlab.com/api/v4/packages/npm/lodash/-/lodash-invalid.tgz'],
  ['malformed filename version on a mirror', 'lodash', 'https://nexus.example/repository/archive/lodash/-/lodash-invalid.tgz'],
  ['GitLab tarball filename version differs', '@acme/ui', 'https://gitlab.com/api/v4/packages/npm/pkg/-/pkg-0.1.2.tgz'],
  ['opaque private route', '@acme/ui', 'https://unknown.example/download'],
  ['private archive filename', '@acme/ui', 'https://downloads.example/archive.tgz'],
  ['GitLab API path without a source declaration', '@acme/ui', 'https://gitlab.com/api/v4/projects/123/repository/archive.tar.gz'],
  ...['archive', 'tarball', 'zipball', '@foo/archive', 'archiver', 'lodash.git'].map(name => [name, name, `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-1.2.3.tgz`]),
  ...['https://nexus.corp/repository/archive/', 'https://npm.corp.example/archive/npm/', 'https://cache.corp/tarball/', 'https://nexus.corp/repository/npm-group/'].map(base => [base, 'react', base + 'react/-/react-1.2.3.tgz']),
];
for (const format of formats) for (const [label, name, url] of retained) test(`${format.label}: ${label} retains identity and accounts for the installation`, () => {
  assertAccounted(format.parser(format.lock(name, '1.2.3', url)), {
    rows: [row(name)], incomplete: false, decisions: [{ key: format.key(name, '1.2.3'), status: 'reported' }],
  });
});

for (const format of formats) test(`${format.label}: renamed private artifacts reach the loopback receiver without diagnostic fields`, async t => {
  const root = project(t); const server = await receiver(t);
  const lock = format.lock('@acme/ui', '1.2.3', 'https://registry.corp/@acme/ui/-/renamed.tgz');
  writeFileSync(join(root, format.file), typeof lock === 'string' ? lock : JSON.stringify(lock));
  const result = await run(root, ['setup', '--no-hook'], server);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(server.hits[0].packages, [{ ecosystem: 'npm', ...row('@acme/ui') }]);
  assert.equal(server.hits[0].incomplete, undefined);
  assert.doesNotMatch(JSON.stringify(server.hits[0]), /classifications|renamed\.tgz|registry\.corp|node_modules/);
});

for (const format of formats) for (const url of [
  'https://registry.npmjs.org/@acme/ui/-/ui-bad.tgz',
  'https://registry.npmjs.org/@acme/ui/-/ui-2.0.0.tgz',
  'https://registry.npmjs.org/@other/ui/-/ui-1.2.3.tgz',
  'https://registry.npmjs.org/@acme/ui/-/@other/ui-1.2.3.tgz',
  'https://registry.npmjs.org/@acme/ui/-/ui-1.2.3%ZZ.tgz',
  'https://registry.npmjs.org/@acme/ui/opaque',
  'https://registry.npmjs.org./@acme/ui/opaque',
  'https://registry.yarnpkg.com/@acme/ui/opaque',
  'https://npm.pkg.github.com/download/@other/ui/1.2.3/abcdef',
  'https://npm.pkg.github.com/download/@acme/ui/1.2.3/not-hex',
  'https://registry.npmjs.org/download/opaque-id',
  'https://registry.yarnpkg.com/packages/opaque-id?download=true',
  'https://npm.pkg.github.com/packages/opaque-id',
  'https://npm.pkg.github.com/download/opaque-id',
  'relative/path',
]) test(`${format.label}: malformed canonical metadata or URL stays incomplete: ${url}`, () => {
  const rows = format.parser(format.lock('@acme/ui', '1.2.3', url));
  assertAccounted(rows, { rows: [], incomplete: true, decisions: [{ key: format.key('@acme/ui', '1.2.3'), status: 'incomplete',
    reason: url.includes('%ZZ') || url === 'relative/path' ? 'malformed resolution' : 'invalid canonical registry route' }] });
});

for (const spec of ['git+https://code.example/r', 'git:repo', 'git@code.example:org/repo', 'github:o/r', 'gitlab:o/r', 'bitbucket:o/r',
  'file:local', 'link:local', 'portal:local', 'workspace:*', 'exec:script', 'https://registry.corp/custom']) {
  test(`shared classifier positively excludes declared source ${spec.split(':')[0]}`, () => {
    assert.deepEqual(lib.classifyPackageSource({ name: 'pkg', version: '1.2.3', specs: [spec], resolution: 'https://registry.corp/opaque' }),
      { status: 'excluded', reason: spec.startsWith('https:') ? 'declared URL dependency' : 'source protocol' });
  });
}

for (const version of ['', 'latest', '01.2.3', '1.02.3', '1.2.03', '1.2.3-01', '1.2.3-rc.01']) test(`invalid semver is incomplete: ${version}`, () => {
  assert.equal(lib.classifyPackageSource({ name: 'pkg', version }).status, 'incomplete');
});

test('classification accounting detects an omitted row instead of trusting an empty inventory', () => {
  assert.throws(() => assertAccounted([], { rows: [], incomplete: false, decisions: [{ key: 'pkg', status: 'reported' }] }));
});

for (const version of ['1.0.0-canary.20241029.abcdef0123456789abcdef0123456789abcdef01', '0.0.0-insiders.4a070ac', '15.0.0-canary-f1a2b3c4d5e6-20241029']) {
  test(`long and mixed semver identifiers remain unchanged: ${version}`, () => assert.equal(lib.screenString(version, 'package version'), version));
}
