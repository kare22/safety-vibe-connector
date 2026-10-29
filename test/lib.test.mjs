// Pure connector regressions; all fixtures use local files and fabricated keys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, cpSync, utimesSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fromPackageLock, fromBunLock, fromYarnLock, fromPnpmLock, keyKind, publicKeyKind, parseEnv, buildReport, findSupabase, withHook, HOOK, appName, detectPlatform, packageManager, normPublicUrl, urlNeedsCleaning, readPackages } from '../lib.mjs';
const jwt = payload => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify(payload)).toString('base64url') + '.sig';
const ANON = jwt({ role: 'anon', ref: 'abcdefghijklmnop' });
const SERVICE = jwt({ role: 'service_role' });


test('key-like hostnames cannot leak through public URL metadata', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-host-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const host of ['sb_secret_private.example', 'svk_private.example', 'eyJhbGciOiJIUzI1NiJ9.example', '%73%62_secret_private.example']) {
    const url = 'https://' + host + '/app';
    assert.equal(normPublicUrl(url), ''); assert.equal(urlNeedsCleaning(url), true);
    assert.equal(buildReport(dir, { url }, {}).url, undefined);
  }
});

test('adversarial source specs are dropped across all lockfile generations', () => {
  const specs = ['git+https://private.example/name/-/name-1.0.0.tgz#semver:^1.0.0', 'github:owner/private#semver:1.0.0', 'git+ssh://git@private.example/repo', 'file:../private-folder', 'link:../private-folder', 'workspace:*'];
  for (const spec of specs) {
    const entry = { version: '1.0.0', resolved: spec };
    assert.deepEqual(fromPackageLock({ lockfileVersion: 1, dependencies: { private: entry } }), []);
    for (const lockfileVersion of [2, 3]) assert.deepEqual(fromPackageLock({ lockfileVersion, packages: { 'node_modules/private': entry } }), []);
    assert.deepEqual(fromYarnLock(`"private@${spec}":\n  version "1.0.0"\n  resolved "${spec}"\n`), []);
    for (const quote of ['', "'", '"']) assert.deepEqual(fromYarnLock(`private@^1.0.0:\n  version "1.0.0"\n  resolved ${quote}${spec}${quote}\n`), []);
    assert.deepEqual(fromYarnLock(`__metadata:\n  version: 6\n"private@${spec}":\n  version: 1.0.0\n  resolution: "private@${spec}"\n`), []);
    assert.deepEqual(fromBunLock(JSON.stringify({ packages: { private: ['private@' + spec, {}] } })), []);
    for (const version of ['5.4', '6.0', '9.0']) {
      const key = version === '5.4' ? '/private/1.0.0' : version === '6.0' ? '/private@1.0.0' : 'private@1.0.0';
      assert.deepEqual(fromPnpmLock(`lockfileVersion: '${version}'\npackages:\n  '${key}':\n    resolution: {tarball: '${spec}', integrity: sha512-x}\n`), []);
    }
  }
  const resolved = 'https://not-a-registry.example/name/-/name-1.0.0.tgz';
  assert.deepEqual(fromPackageLock({ dependencies: { name: { version: '1.0.0', resolved } } }), [{ name: 'name', version: '1.0.0' }]);
});

test('npm source declarations exclude hoisted and renamed non-registry packages', () => {
  for (const spec of ['git+https://example.com/repo#semver:^1.0.0', 'github:owner/private', 'file:../private', 'link:../private', 'workspace:*', 'https://example.com/private.tgz']) {
    for (const lockfileVersion of [2, 3]) {
      const packages = { '': { dependencies: { private: spec } }, 'node_modules/private': { name: 'private-real-name', version: '1.0.0' } };
      assert.deepEqual(fromPackageLock({ lockfileVersion, packages }), []);
    }
    assert.deepEqual(fromPackageLock({ lockfileVersion: 1, dependencies: { parent: { version: '1.0.0', requires: { private: spec } }, private: { version: '1.0.0' } } }), [{ name: 'parent', version: '1.0.0' }]);
  }
});

test('installed fallback excludes hoisted git/file names and installed source metadata', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-hoisted-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { parent: '^1.0.0' } }));
  const entries = {
    'a-private': { name: 'a-private', version: '1.0.0' },
    parent: { name: 'parent', version: '1.0.0', dependencies: { 'a-private': 'git+https://example.com/repo#semver:^1', local: 'file:../local' } },
    local: { name: 'local', version: '1.0.0' },
    metadata: { name: 'metadata', version: '1.0.0', _resolved: 'github:owner/private' },
  };
  for (const [name, pkg] of Object.entries(entries)) {
    const folder = join(dir, 'node_modules', name); mkdirSync(folder, { recursive: true });
    writeFileSync(join(folder, 'package.json'), JSON.stringify(pkg));
  }
  // only the manifest declaration is eligible, never installed names/versions.
  assert.deepEqual(readPackages(dir), { packages: [{ ecosystem: 'npm', name: 'parent', version: '^1.0.0' }], source: 'none', noLockfile: true });
});

test('lockfile parsers: npm v3, bun.lock, yarn v1/berry, pnpm', () => {
  assert.deepEqual(fromPackageLock({ packages: { '': { name: 'app' }, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/a/node_modules/@s/b': { version: '1.0.0' } } }),
    [{ name: 'lodash', version: '4.17.20' }, { name: '@s/b', version: '1.0.0' }]);
  const bun = `{
    // comment
    "lockfileVersion": 1,
    "packages": {
      "react": ["react@18.3.1", "", {}, "sha512-x"],
      "@scope/x": ["@scope/x@2.0.0", "", {}, "sha512-y"],
      "ws": ["my-ws@workspace:packages/ws"],
    },
  }`;
  assert.deepEqual(fromBunLock(bun), [{ name: 'react', version: '18.3.1' }, { name: '@scope/x', version: '2.0.0' }]);
  const y1 = '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n  resolved "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"\n\nlodash@^4.17.0:\n  version "4.17.21"\n';
  assert.deepEqual(fromYarnLock(y1), [{ name: '@babel/core', version: '7.24.0' }, { name: 'lodash', version: '4.17.21' }]);
  const berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n';
  assert.deepEqual(fromYarnLock(berry), [{ name: 'lodash', version: '4.17.21' }]);
  const pnpm = "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-test}\n\n  '@scope/x@1.2.3':\n    resolution: {integrity: sha512-test}\n\n  /react@18.3.1:\n    resolution: {integrity: sha512-test}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n";
  assert.deepEqual(fromPnpmLock(pnpm), [{ name: 'lodash', version: '4.17.21' }, { name: '@scope/x', version: '1.2.3' }, { name: 'react', version: '18.3.1' }]);
});

test('only public Supabase keys are ever accepted', () => {
  assert.equal(keyKind(ANON), 'anon');
  assert.equal(keyKind('sb_publishable_abc123def456'), 'publishable');
  assert.equal(keyKind(SERVICE), 'secret');
  assert.equal(keyKind('sb_secret_abc123'), 'secret');
  assert.equal(keyKind('not-a-key'), 'unknown');
});

test('lockfile entries that are not registry versions (git/file/link URLs) are never reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svc-'));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 1, dependencies: {
    lodash: { version: '4.17.21' },
    priv: { version: 'git+https://user:TOKEN@git.example/repo.git#abc' },
    local: { version: 'file:../private-project' },
  } }));
  const { packages } = readPackages(dir);
  assert.deepEqual(packages.map((x) => x.name), ['lodash']);
  assert.ok(!JSON.stringify(packages).includes('TOKEN'));
});

test('a valid JSON lockfile with no dependencies is reported as such (not as "no lockfile")', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svempty-'));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' } } }));
  assert.deepEqual(readPackages(dir), { packages: [], source: 'package-lock.json' });
  const dir2 = mkdtempSync(join(tmpdir(), 'svnolock-'));
  assert.deepEqual(readPackages(dir2), { packages: [], source: 'none', noLockfile: true });
});

test('hook chaining is conservative and idempotent', () => {
  for (const value of ['node a.js &', 'a;', 'a ||', 'a |', 'x &&', 'echo "x"']) assert.equal(withHook(value).status, 'unsafe');
  assert.equal(withHook('').script, HOOK);
  assert.equal(withHook('node a.js').script, 'node a.js && (' + HOOK + ')');
  assert.equal(withHook('a && b').script, 'a && b && (' + HOOK + ')');
  for (const value of [HOOK, 'x && (' + HOOK + ')']) assert.equal(withHook(value).status, 'already there');
  assert.equal(withHook('x && ' + HOOK).script, 'x && (' + HOOK + ')');
});

test('lock choice, malformed fallbacks, workspaces, dev and optional inventory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svlocks-'));
  const npm = { packages: { 'node_modules/a': { version: '1.0.0', dev: true }, 'node_modules/local': { version: '1.0.0', link: true } } };
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(npm));
  writeFileSync(join(dir, 'yarn.lock'), 'b@^2.0.0:\n  version "2.0.0"\n');
  utimesSync(join(dir, 'package-lock.json'), 10, 10); utimesSync(join(dir, 'yarn.lock'), 20, 20);
  assert.equal(readPackages(dir).source, 'yarn.lock');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ packageManager: 'npm@10' }));
  assert.equal(readPackages(dir).source, 'package-lock.json'); assert.equal(readPackages(dir).packages[0].dev, true);
  writeFileSync(join(dir, 'package-lock.json'), '{'); assert.equal(readPackages(dir).source, 'yarn.lock');
  writeFileSync(join(dir, 'bun.lock'), '{'); utimesSync(join(dir, 'bun.lock'), 30, 30); assert.equal(readPackages(dir).source, 'yarn.lock');
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(npm));
  const child = join(dir, 'packages', 'web'); mkdirSync(child, { recursive: true }); writeFileSync(join(child, 'package.json'), '{}');
  assert.equal(readPackages(child).source, 'none');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ packageManager: 'npm@10', workspaces: ['packages/*'] }));
  assert.equal(readPackages(child).packages[0].name, 'a');
  const entries = { packages: { 'node_modules/a': { version: '1.0.0', optional: true, os: ['darwin'] }, 'node_modules/b': { version: '1.0.0', optional: true, cpu: ['arm64'] }, 'node_modules/c': { version: '1.0.0', dev: true } } };
  assert.deepEqual(fromPackageLock(entries), [{ name: 'a', version: '1.0.0' }, { name: 'b', version: '1.0.0' }, { name: 'c', version: '1.0.0', dev: true }]);
  assert.equal(fromPnpmLock("packages:\n  /x@1.0.0:\n    resolution: {integrity: sha512-test}\n    dev: true\n")[0].dev, true);
  assert.equal(packageManager(child, {}), 'npm');
  const huge = { packages: Object.fromEntries(Array.from({ length: 5001 }, (_, i) => ['node_modules/p' + i, { version: '1.0.0' }])) };
  writeFileSync(join(child, 'package-lock.json'), JSON.stringify(huge));
  assert.equal(readPackages(child).total, 5001); assert.equal(buildReport(child, {}, {}).truncated, true); assert.equal(readPackages(child).packages.length, 5000);
});

test('identity uses real names, project markers, hosts and CI in order', () => {
  const parent = mkdtempSync(join(tmpdir(), 'svidentity-')); const dir = join(parent, 'web'); mkdirSync(dir);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'react-example', dependencies: { '@google/genai': '*' } }));
  assert.equal(appName(dir), ''); assert.equal(appName(dir, 'my-app', 'https://notes.lovable.app'), 'notes');
  assert.equal(appName(dir, 'email-template-editor'), 'email-template-editor');
  assert.equal(appName(dir, '', 'https://example.com'), 'example.com');
  assert.equal(appName(dir, '', 'https://notes.example.com'), 'notes.example.com', 'a dotted custom domain is a name, not a JWT');
  assert.equal(detectPlatform(dir, { VERCEL: '1' }, 'https://x.lovable.app'), 'Google AI Studio');
  writeFileSync(join(dir, 'package.json'), '{}');
  assert.equal(detectPlatform(dir, { VERCEL: '1' }, 'https://x.bolt.host'), 'Bolt');
  mkdirSync(join(dir, '.bolt')); assert.equal(detectPlatform(dir, {}, 'https://x.lovable.app'), 'Bolt');
});

test('binary bun and corrupt locks send no packages (no installed-modules fallback)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svbun-'));
  writeFileSync(join(dir, 'bun.lockb'), Buffer.from([1, 2, 3]));
  mkdirSync(join(dir, 'node_modules', 'a'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'a', 'package.json'), '{"name":"a","version":"1.0.0"}');
  assert.deepEqual(readPackages(dir), { packages: [], source: 'none', noLockfile: true, binaryBun: true });
  writeFileSync(join(dir, 'bun.lock'), '{'); assert.deepEqual(readPackages(dir), { packages: [], source: 'none', noLockfile: true, binaryBun: true });
  rmSync(join(dir, 'bun.lockb')); assert.deepEqual(readPackages(dir), { packages: [], source: 'none', noLockfile: true });
  writeFileSync(join(dir, 'package-lock.json'), 'not json'); assert.deepEqual(readPackages(dir), { packages: [], source: 'none', noLockfile: true });
});

test('all supported host labels and package manager hints', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svhosts-'));
  for (const [suffix, label] of Object.entries({ 'lovable.app': 'Lovable', 'replit.app': 'Replit', 'repl.co': 'Replit', 'bolt.host': 'Bolt', 'base44.app': 'Base44', 'emergent.host': 'Emergent', 'emergentagent.com': 'Emergent', 'softgen.ai': 'Softgen', 'softgen.dev': 'Softgen', 'lp.dev': 'Leap', 'vercel.app': 'Vercel', 'netlify.app': 'Netlify', 'run.app': 'Google Cloud Run' })) assert.equal(detectPlatform(dir, { NETLIFY: '1' }, 'https://notes.' + suffix), label);
  for (const manager of ['npm', 'pnpm', 'bun', 'yarn']) {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ packageManager: manager + '@1.0.0' })); assert.equal(packageManager(dir, {}), manager);
    writeFileSync(join(dir, 'package.json'), '{}'); assert.equal(packageManager(dir, { npm_config_user_agent: manager + '/1.0.0' }), manager);
  }
  writeFileSync(join(dir, 'metadata.json'), '{"requestFramePermissions":[]}'); assert.equal(detectPlatform(dir, {}), 'Google AI Studio');
});

test('client fallback keys are validated and warnings contain names only', () => {
  const dir = mkdtempSync(join(tmpdir(), 'svclient-')); mkdirSync(join(dir, 'src', 'integrations', 'supabase'), { recursive: true });
  const file = join(dir, 'src', 'integrations', 'supabase', 'client.ts');
  writeFileSync(file, 'const URL = "https://abc.supabase.co"; const SUPABASE_ANON_KEY = "' + SERVICE + '";');
  assert.equal(findSupabase(dir, {}).key, ''); assert.deepEqual(findSupabase(dir, {}).warnings, ['src/integrations/supabase/client.ts']);
  writeFileSync(file, 'const URL = "https://abc.supabase.co"; const SUPABASE_ANON_KEY = "' + ANON + '";');
  assert.equal(findSupabase(dir, {}).key, ANON);
  assert.equal(publicKeyKind('sb_publishable_' + 'a'.repeat(200)), 'publishable');
  assert.equal(publicKeyKind('sb_publishable_' + 'a'.repeat(201)), null);
  assert.equal(publicKeyKind(jwt({ role: 'admin' })), null);
  assert.equal(publicKeyKind(jwt({ role: 'anon', pad: 'x'.repeat(2000) })), null);
});

test('parent inventory requires workspace markers and respects boundaries', t => {
  const dir = mkdtempSync(join(tmpdir(), 'svparents-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.git')); const child = join(dir, 'child'); mkdirSync(child);
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' } } }));
  assert.equal(readPackages(child).source, 'none');
  for (const workspaces of [['child'], { packages: ['child'] }]) {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ workspaces }));
    assert.equal(readPackages(child).source, 'package-lock.json');
  }
  writeFileSync(join(dir, 'package.json'), '{}'); writeFileSync(join(dir, 'pnpm-workspace.yaml'), "packages:\n  - 'child'\n");
  assert.equal(readPackages(child).source, 'package-lock.json');
  mkdirSync(join(child, '.git')); assert.equal(readPackages(child).source, 'none');
  let deep = dir;
  for (let i = 0; i < 7; i++) { deep = join(deep, 'level'); mkdirSync(deep); }
  assert.equal(readPackages(deep).source, 'none');
});

test('Supabase selection skips rejected values in environment and client files', t => {
  const dir = mkdtempSync(join(tmpdir(), 'svselect-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const rejected of ['invalid', SERVICE, 'sb_secret_fixture']) {
    rmSync(join(dir, 'src', 'integrations', 'supabase', 'client.ts'), { force: true });
    const found = findSupabase(dir, { VITE_SUPABASE_URL: 'https://abc.supabase.co', VITE_SUPABASE_PUBLISHABLE_KEY: rejected, VITE_SUPABASE_ANON_KEY: ANON });
    assert.equal(found.key, ANON); assert.equal(found.kind, 'anon');
    assert.deepEqual(found.warnings, rejected !== SERVICE ? [] : ['VITE_SUPABASE_PUBLISHABLE_KEY']);
    mkdirSync(join(dir, 'src', 'integrations', 'supabase'), { recursive: true });
    writeFileSync(join(dir, 'src', 'integrations', 'supabase', 'client.ts'), 'const URL = "https://abc.supabase.co"; const SUPABASE_PUBLISHABLE_KEY = "' + rejected + '"; const SUPABASE_ANON_KEY = "' + ANON + '";');
    assert.equal(findSupabase(dir, {}).key, ANON);
    assert.deepEqual(findSupabase(dir, {}).warnings, rejected !== SERVICE ? [] : ['src/integrations/supabase/client.ts']);
  }
});

test('connector docs describe data, flags, workspace boundaries and hook; source text is ASCII', () => {
  for (const name of ['README.md', 'AGENTS.md']) {
    const doc = readFileSync(new URL('../' + name, import.meta.url), 'utf8');
    assert.match(doc, /reports your package list so we can warn you about vulnerable dependencies/);
    assert.match(doc, /--flag=value.*--flag value/); assert.match(doc, /values starting with a dash/);
    assert.match(doc, /only at workspace roots/); assert.match(doc, /six parent levels/);
    assert.match(doc, /scan --quiet \|\| exit 0/); assert.match(doc, /Without a local key it skips reporting/);
  }
  for (const path of ['../README.md', '../AGENTS.md', '../cli.mjs', '../lib.mjs', '../package.json']) {
    assert.doesNotMatch(readFileSync(new URL('./' + path, import.meta.url), 'utf8'), /[^\x00-\x7F]/);
  }
});

test('identity, environment, JWT payload and URL hygiene', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-hygiene-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'package.json'), '{"name":"safe-app"}');
  for (const candidate of [ANON, SERVICE, 'sb_publishable_abcdefgh', 'prefix-SVK_abcdef', jwt({ role: 'anon', extra: 'sb_secret_fixture' })]) assert.equal(appName(dir, candidate), '');
  assert.equal(appName(dir, 'Notes! <team> @foo/bar._-'), 'Notes team @foo/bar._-');
  assert.equal(appName(dir, 'x'.repeat(100)), '');
  assert.equal(appName(dir, 'long name '.repeat(12)).length, 80);
  assert.equal(buildReport(dir, { environment: 'prod! @/a_b-c' }, {}).environment, 'proda_b-c');
  assert.equal(buildReport(dir, { environment: 'x'.repeat(30) }, {}).environment.length, 20);
  for (const payload of [{ role: 'anon', extra: 'sb_secret_fixture' }, { role: 'anon', extra: 'service_role' }, { role: 'anon', ref: 'INVALID' }, { role: 'anon', ref: 123 }]) assert.equal(publicKeyKind(jwt(payload)), null);
  assert.equal(publicKeyKind(jwt({ role: 'anon' })), 'anon');
  for (const path of ['/a@b', '/a%3fb', '/a%23b', '/a%26b', '/a%3Db']) assert.equal(normPublicUrl('https://example.com' + path), 'https://example.com');
});

test('ancestor inventory requires matching workspace membership', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-members-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.git')); const child = join(dir, 'apps', 'nested', 'web'); mkdirSync(child, { recursive: true });
  writeFileSync(join(dir, 'package-lock.json'), '{"packages":{"node_modules/a":{"version":"1.0.0"}}}');
  for (const [globs, source] of [[[], 'none'], [['apps/*'], 'none'], [['!apps/**'], 'none'], [['else/**'], 'none'], [['apps/**'], 'package-lock.json'], [['apps/nested/web'], 'package-lock.json'], [['apps/*/*'], 'package-lock.json'], [['apps/nest*/w*b'], 'package-lock.json']]) {
    for (const workspaces of [globs, { packages: globs }]) {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ workspaces })); assert.equal(readPackages(child).source, source);
    }
    writeFileSync(join(dir, 'package.json'), '{}');
    writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'packages:\n' + globs.map(g => "  - '" + g + "'\n").join(''));
    assert.equal(readPackages(child).source, source);
    writeFileSync(join(dir, 'pnpm-workspace.yaml'), '');
  }
});

test('shell expansion scripts are unsafe', () => {
  for (const script of ['echo $HOME', 'echo %PATH%', 'echo !VAR!', 'echo ${HOME}']) assert.equal(withHook(script).status, 'unsafe');
});

test('whole public path allowlist and cleaning agree', () => {
  for (const path of ['/cb&token=SECRET', '/a=b', '/p%26x', '/@u', '/eyJhbGciOi.x.y', '/SB_token', '/SVK_token', '/' + 'a'.repeat(41), '/a'.repeat(9), '/a//b']) {
    assert.equal(normPublicUrl('https://h' + path), /eyJ|SVK_|a{41}/.test(path) ? '' : 'https://h');
    assert.equal(urlNeedsCleaning('https://h' + path), true);
  }
  for (const path of ['/my-app/dashboard', '/my-app/', '/']) {
    assert.equal(normPublicUrl('https://h' + path), 'https://h' + (path === '/' ? '' : path));
    assert.equal(urlNeedsCleaning('https://h' + path), false);
  }
  for (const url of ['https://u:p@h/a', 'https://h/a?q=x', 'https://h/a#x']) assert.equal(urlNeedsCleaning(url), true);
});

test('JWT claims are allowlisted and primitive', () => {
  for (const payload of [{ role: 'anon', db_password: 'x' }, { role: 'anon', aud: {} }, { role: 'anon', aud: [] }, { role: 'anon', exp: null }, { role: 'anon', nbf: true }, { role: 'anon', iss: 'other' }, { role: 'anon', sub: 'x'.repeat(101) }, ...['sb_secret_x', 'SVK_x', 'eyJx'].map(sub => ({ role: 'anon', sub })), {}, { role: 1 }]) {
    assert.equal(publicKeyKind(jwt(payload)), null); assert.equal(keyKind(jwt(payload)), 'unknown');
  }
  assert.equal(publicKeyKind(jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'anon', iat: 1, exp: 2 })), 'anon');
  assert.equal(publicKeyKind(jwt({ iss: 'supabase-demo', role: 'anon', aud: 'authenticated', sub: 'x', nbf: 1 })), 'anon');
  assert.equal(keyKind(jwt({ role: 'service_role' })), 'secret');
});

test('identity and environment checked before and after sanitising', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-label-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'package.json'), '{"name":"safe-app"}');
  for (const value of ['sv<!>k_token', 'sb_<!>secret_abcdef', 'e<!>yJtoken', 'sb_publishable_abc<!>defgh']) assert.equal(appName(dir, value), '');
  for (const value of ['sb_secret_abcdef', 'sv<!>k_token', 'e<!>yJtoken', 'sb_publishable_abcdefgh']) assert.equal(buildReport(dir, {}, { SAFETYVIBE_ENV: value }).environment, undefined);
});

test('workspace exclusion globs exclude members in all formats', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-excluded-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.git')); const child = join(dir, 'packages', 'excluded'); mkdirSync(child, { recursive: true });
  writeFileSync(join(dir, 'package-lock.json'), '{"packages":{"node_modules/a":{"version":"1.0.0"}}}');
  for (const globs of [['packages/*', '!packages/excluded'], ['!packages/**', 'packages/*']]) {
    for (const workspaces of [globs, { packages: globs }]) {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ workspaces })); assert.equal(readPackages(child).source, 'none');
    }
    writeFileSync(join(dir, 'package.json'), '{}');
    writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'packages:\n' + globs.map(g => "  - '" + g + "'\n").join(''));
    assert.equal(readPackages(child).source, 'none'); writeFileSync(join(dir, 'pnpm-workspace.yaml'), '');
  }
});

test('0.2.2 registry resolution filtering in every lockfile format', () => {
  const good = 'https://private.example/npm/registry-pkg/-/registry-pkg-1.2.3.tgz';
  const entries = { 'registry-pkg': { version: '1.2.3', resolved: good }, 'private-git-dep': { version: '2.0.0', resolved: 'git+https://private.example/repo.git' }, 'tarball-dep': { version: '3.1.4', resolved: 'https://private.example/archive.tgz' } };
  const expected = [{ name: 'registry-pkg', version: '1.2.3' }, { name: 'tarball-dep', version: '3.1.4' }];
  assert.deepEqual(fromPackageLock({ dependencies: entries }), expected);
  for (const lockfileVersion of [2, 3]) assert.deepEqual(fromPackageLock({ lockfileVersion, packages: Object.fromEntries(Object.entries(entries).map(([k,v]) => ['node_modules/'+k,v])) }), expected);
  assert.deepEqual(fromBunLock(JSON.stringify({ packages: Object.fromEntries(Object.entries(entries).map(([k,v]) => [k,[k+'@'+v.version,k === 'registry-pkg' ? '' : v.resolved]])) })), expected);
  assert.deepEqual(fromYarnLock(Object.entries(entries).map(([k,v]) => `${k}@^${v.version}:\n  version "${v.version}"\n  resolved "${v.resolved}"\n`).join('\n')), expected);
  assert.deepEqual(fromYarnLock('__metadata:\n  version: 6\n'+Object.entries(entries).map(([k,v]) => `"${k}@${k === 'registry-pkg' ? 'npm:^'+v.version : v.resolved}":\n  version: ${v.version}\n  resolution: "${k}@${k === 'registry-pkg' ? 'npm:'+v.version : v.resolved}"\n`).join('\n')), expected.slice(0, 1));
  for (const separator of ['@','/']) assert.deepEqual(fromPnpmLock('packages:\n'+Object.entries(entries).map(([k,v]) => `  /${k}${separator}${v.version}:\n    resolution: {integrity: sha512-test${k === 'registry-pkg' ? '' : ', tarball: '+v.resolved}}\n`).join('\n')), expected);
  assert.deepEqual(fromPnpmLock('packages:\n  /@scope/pkg/1.2.3_peer@x:\n    resolution: {integrity: sha512-x}\n'), [{ name: '@scope/pkg', version: '1.2.3' }]);
  assert.deepEqual(fromPackageLock({ dependencies: { a: { version:'git+https://example.com/a' }, b: { version:'2.0.0',link:true } } }), []);
});

test('0.2.2 installed node_modules (incl. nested and private sources) are never reported', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-nested-')); t.after(() => rmSync(dir, { recursive:true, force:true }));
  writeFileSync(join(dir,'package.json'), JSON.stringify({ dependencies: { 'private-git-dep':'user/private', 'tarball-dep':'https://example.com/a.tgz', debug:'^4.0.0' } }));
  for (const [path,name,version] of [['private-git-dep','private-git-dep','2.0.0'],['tarball-dep','tarball-dep','3.1.4'],['debug','debug','4.0.0'],['debug/node_modules/ms','ms','2.0.0']]) {
    const dest=join(dir,'node_modules',path); mkdirSync(dest,{recursive:true}); writeFileSync(join(dest,'package.json'),JSON.stringify({name,version}));
  }
  for (const binary of [false,true]) {
    if(binary) writeFileSync(join(dir,'bun.lockb'),'binary');
    assert.deepEqual(readPackages(dir).packages,[{ecosystem:'npm',name:'debug',version:'^4.0.0'}]); assert.equal(readPackages(dir).source,'none'); assert.equal(readPackages(dir).noLockfile,true);
  }
});

test('0.2.2 excluded lockfile entries cannot reappear through installed fallback',t=>{
  const dir=mkdtempSync(join(tmpdir(),'sv-filtered-lock-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  mkdirSync(join(dir,'node_modules','private-git-dep'),{recursive:true});writeFileSync(join(dir,'node_modules','private-git-dep','package.json'),JSON.stringify({name:'private-git-dep',version:'2.0.0'}));
  for(const [file,text] of [['yarn.lock','"private-git-dep@^2.0.0":\n  version "2.0.0"\n  resolved "git+https://private.example/repo"\n'],['pnpm-lock.yaml','packages:\n  private-git-dep@2.0.0:\n    resolution: {repo: https://private.example/repo, integrity: sha512-x}\n']]) {
    writeFileSync(join(dir,file),text);assert.deepEqual(readPackages(dir).packages,[]);assert.equal(readPackages(dir).source,file);rmSync(join(dir,file));
  }
  assert.deepEqual(fromYarnLock('__metadata:\n  version: 6\n"private-git-dep@npm:^2.0.0":\n  version: 2.0.0\n  resolution: "private-git-dep@https://private.example/@npm:repo"\n'),[]);
});

test('only client-exposed Supabase variable names are read', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-env-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, '.env'), 'SUPABASE_URL=https://abc.supabase.co\nSUPABASE_ANON_KEY=' + ANON + '\nSUPABASE_PUBLISHABLE_KEY=sb_publishable_abc123def456\n');
  assert.deepEqual(findSupabase(dir, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_ANON_KEY: ANON }), { url: '', key: '', kind: 'none', warnings: [], serviceVariables: [] });
  assert.equal(buildReport(dir, {}, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_ANON_KEY: ANON }).supabase, null);
  for (const prefix of ['VITE_', 'NEXT_PUBLIC_', 'EXPO_PUBLIC_', 'PUBLIC_', 'REACT_APP_', 'NUXT_PUBLIC_']) {
    writeFileSync(join(dir, '.env'), prefix + 'SUPABASE_URL=https://abc.supabase.co\n' + prefix + 'SUPABASE_ANON_KEY=' + ANON + '\n');
    assert.deepEqual(findSupabase(dir, {}).key, ANON, prefix);
  }
});

test('a large monorepo uses only selected manifest declarations (never installed/private names)', async () => {
  const { readPackages } = await import('../lib.mjs');
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'sv-big-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'root', private: true, workspaces: ['apps/*'] }));
    writeFileSync(join(dir, 'bun.lockb'), 'binary');
    mkdirSync(join(dir, 'apps', 'web'), { recursive: true });
    writeFileSync(join(dir, 'apps', 'web', 'package.json'), JSON.stringify({ name: 'web', dependencies: { left: '1.0.0' } }));
    for (let i = 0; i < 2100; i++) mkdirSync(join(dir, 'filler', 'd' + i), { recursive: true });
    mkdirSync(join(dir, 'zz', 'late'), { recursive: true });
    writeFileSync(join(dir, 'zz', 'late', 'package.json'), JSON.stringify({ name: 'late', dependencies: { 'priv-late': 'git+https://example.invalid/priv.git' } }));
    for (const [n, v] of [['left', '1.0.0'], ['priv-late', '1.2.3']]) { mkdirSync(join(dir, 'node_modules', n), { recursive: true }); writeFileSync(join(dir, 'node_modules', n, 'package.json'), JSON.stringify({ name: n, version: v })); }
    const r = readPackages(join(dir, 'apps', 'web'));
    assert.deepEqual(r.packages, [{ ecosystem: 'npm', name: 'left', version: '1.0.0' }]);
    assert.equal(buildReport(join(dir, 'apps', 'web'), {}, {}).versions_source, 'declared');
    assert.equal(r.source, 'none');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('0.2.2 Supabase source fallback reads only clearly client-side files', async t => {
  const { clientSource } = await import('../lib.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'sv-srv-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'lib'), { recursive: true });
  const file = join(dir, 'lib', 'supabase.ts');
  const body = 'const URL = "https://abc.supabase.co"; const SUPABASE_ANON_KEY = "' + ANON + '";';
  for (const header of ['import "server-only";\n', "import 'server-only'\n", 'require("server-only");\n', '"use server";\n', "'use server'\n"]) {
    writeFileSync(file, header + body);
    assert.deepEqual(findSupabase(dir, {}), { url: '', key: '', kind: 'none', warnings: [], serviceVariables: [] }, header);
  }
  writeFileSync(file, body); assert.equal(findSupabase(dir, {}).key, ANON);
  for (const path of ['server/supabase.ts', 'src/api/supabase.ts', 'app/api/route.ts', 'pages/api/x.ts', 'supabase/functions/x/index.ts', 'functions/x.ts', 'netlify/functions/x.ts', 'middleware.ts', 'src/lib/db.server.ts', 'src\\server\\x.ts'])
    assert.equal(clientSource(path, body), false, path);
  for (const path of ['src/integrations/supabase/client.ts', 'src/lib/supabase.ts', 'lib/supabase.ts', 'utils/supabase.ts'])
    assert.equal(clientSource(path, body), true, path);
});

test('server-only markers with comments or odd spacing still exclude the file', async () => {
  const { clientSource } = await import('../lib.mjs');
  for (const text of ['import/* c */ "server-only";', "import /* x */ 'server-only'", '/* c */ "use server";\nexport const a = 1', "const x = require ( /* y */ 'server-only' )", '// note\n"use server"']) {
    assert.equal(clientSource('src/lib/supabase.ts', text), false, text);
  }
  assert.equal(clientSource('src/lib/supabase.ts', 'export const url = import.meta.env.VITE_SUPABASE_URL'), true);
});

test('0.3.0 generic client tokens only flag identifiable Supabase secrets', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-token-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'lib'));
  const file = join(dir, 'lib', 'supabase.ts');
  const env = { VITE_SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co', VITE_SUPABASE_ANON_KEY: ANON };
  const publicShape = buildReport(dir, {}, env).supabase;
  assert.equal(publicShape.key_kind, 'anon');
  for (const source of ['process', 'dotenv', 'literal']) {
    const token = jwt({ role: source === 'literal' ? 'user' : 'authenticated' });
    writeFileSync(join(dir, '.env'), source === 'dotenv' ? 'VITE_SOME_TOKEN=' + token : '');
    writeFileSync(file, source === 'literal' ? 'const token = "' + token + '";' : '');
    const values = { ...env, ...(source === 'process' ? { VITE_SOME_TOKEN: token } : {}) };
    assert.deepEqual(findSupabase(dir, values).warnings, [], source);
    assert.deepEqual(buildReport(dir, {}, values).supabase, publicShape, source);
  }
  for (const source of ['process', 'dotenv', 'literal-secret', 'literal-service', 'named-env', 'named-assignment']) {
    const values = { ...env };
    writeFileSync(join(dir, '.env'), source === 'dotenv' ? 'VITE_SUPABASE_SERVICE_ROLE_KEY=' + SERVICE : '');
    writeFileSync(file, source === 'literal-secret' ? 'const token = "sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";'
      : source === 'literal-service' ? 'const token = "' + SERVICE + '";'
      : source === 'named-assignment' ? 'const SUPABASE_ANON_KEY = "' + SERVICE + '";' : '');
    if (source === 'process') values.VITE_SUPABASE_SERVICE_ROLE_KEY = SERVICE;
    if (source === 'named-env') values.VITE_SUPABASE_PUBLISHABLE_KEY = SERVICE;
    assert.equal(findSupabase(dir, values).warnings.length, 1, source);
    assert.deepEqual(buildReport(dir, {}, values).supabase, { project_ref: 'abcdefghijklmnopqrst', host: 'abcdefghijklmnopqrst.supabase.co', secret_key_exposed_client_side: true }, source);
  }
});

test('0.3.1 fp-lovable-fixture and minified guards preserve public fingerprints', t => {
  const dir = mkdtempSync(join(tmpdir(), 'fp-lovable-fixture-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'src/integrations/supabase'), { recursive: true });
  const file = join(dir, 'src/integrations/supabase/client.ts');
  const key = 'sb_publishable_' + 'p7'.repeat(16);
  const base = `const SUPABASE_URL = "https://lovablefixtureref000.supabase.co"; const SUPABASE_PUBLISHABLE_KEY = "${key}"; createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);`;
  const fullSecret = 'sb_secret_' + 'a1'.repeat(20);
  const guards = [
    'if (SUPABASE_PUBLISHABLE_KEY.startsWith("sb_secret_")) throw new Error("unexpected key");',
    'xh=e=>e.startsWith(`sb_publishable_`)||e.startsWith(`sb_secret_`)\nfunction Bh(e){return e.startsWith(`sb_publishable_`)||e.startsWith(`sb_secret_`)}',
    '"sb_secret_" === k; k !== \'sb_secret_\'; k.includes(\'sb_secret_\'); k.indexOf("sb_secret_"); const k2 = \'sb_secret_abc\';',
    'const k = "' + SERVICE.split('.').slice(0, 2).join('.') + '";',
  ];
  for (const guard of guards) {
    writeFileSync(file, base + guard);
    assert.deepEqual(findSupabase(dir, {}).warnings, []);
    assert.deepEqual(buildReport(dir, {}, {}).supabase, { project_ref: 'lovablefixtureref000', host: 'lovablefixtureref000.supabase.co', key_kind: 'publishable', key_fingerprint: createHash('sha256').update(key).digest('hex').slice(0, 8) });
  }
  // Full secrets in client-side comparisons are visible to visitors.
  for (const code of [
    ...['startsWith', 'endsWith', 'includes', 'indexOf'].map(method => `k.${method}(\`${fullSecret}\`);`),
    ...['===', '==', '!==', '!='].flatMap(op => [`k ${op} '${fullSecret}';`, `'${fullSecret}' ${op} k;`]),
  ]) {
    writeFileSync(file, base + code);
    assert.deepEqual(findSupabase(dir, {}).warnings, ['src/integrations/supabase/client.ts']);
    assert.equal(buildReport(dir, {}, {}).supabase.secret_key_exposed_client_side, true);
    assert.ok(!JSON.stringify(buildReport(dir, {}, {})).includes(fullSecret));
  }
  for (const value of [fullSecret, SERVICE]) {
    writeFileSync(file, base + `const k = "${value}";`);
    assert.deepEqual(findSupabase(dir, {}).warnings, ['src/integrations/supabase/client.ts']);
    const body = buildReport(dir, {}, {}); assert.equal(body.supabase.secret_key_exposed_client_side, true); assert.equal(body.supabase.key_fingerprint, undefined);
    assert.ok(!JSON.stringify(body).includes(value));
  }
  writeFileSync(file, base);
  for (const value of ['sb_secret_', 'sb_secret_abc', 'sb_secret_' + 'a'.repeat(19), 'sb_secret_' + '!'.repeat(40), SERVICE.split('.').slice(0, 2).join('.')]) {
    const env = { VITE_SUPABASE_ANON_KEY: value };
    assert.deepEqual(findSupabase(dir, env).warnings, []); assert.equal(buildReport(dir, {}, env).supabase.key_kind, 'publishable');
    assert.equal(publicKeyKind(value), null);
  }
});

test('Published docs cite the exact offline return and full payload fields', () => {
  const cli = readFileSync(new URL('../cli.mjs', import.meta.url), 'utf8'); const lines = cli.split('\n');
  const start = lines.findIndex(line => line.trim() === "if (flags['dry-run']) {");
  const returns = lines.findIndex((line, i) => i > start && line.trim() === 'return 0;');
  const fetches = lines.map((line, i) => line.includes('fetch(') ? i : -1).filter(i => i >= 0);
  assert.equal(fetches.length, 1); assert.ok(returns < fetches[0]);
  for (const file of ['README.md', 'AGENTS.md']) {
    const doc = readFileSync(new URL('../' + file, import.meta.url), 'utf8');
    const cited = /cli\.mjs line (\d+): `return 0;` inside `if \(flags\['dry-run'\]\)`/.exec(doc);
    assert.ok(cited); assert.equal(Number(cited[1]), returns + 1); assert.equal(lines[Number(cited[1]) - 1].trim(), 'return 0;');
    assert.match(doc, /escaping read symlink or junction stops the whole report before any network request or config write/);
    assert.match(doc, /absent Git binary \(ENOENT\) is treated as an unversioned project/);
    assert.match(doc, /makes no network call and writes nothing unless you pass `--out`/);
    assert.match(doc, /not just their key names/); assert.doesNotMatch(doc, /0\.2\.3/);
    for (const field of ['v', 'name', 'url', 'platform', 'environment', 'lockfile', 'versions_source', 'source', 'packages', 'truncated', 'incomplete', 'supabase', 'packages[].ecosystem', 'packages[].name', 'packages[].version', 'packages[].dev', 'supabase.project_ref', 'supabase.host', 'supabase.key_kind', 'supabase.key_fingerprint', 'supabase.secret_key_exposed_client_side']) assert.ok(doc.includes('`' + field + '`'), field);
    for (const path of ['src/integrations/supabase/client.ts', 'src/integrations/supabase/client.js', 'src/lib/supabase.ts', 'src/lib/supabase.js', 'lib/supabase.ts', 'utils/supabase.ts']) assert.ok(doc.includes(path));
    assert.doesNotMatch(doc, /github\.com\/kare22\/safetyvibe-connect|provenance|public repository/i);
    assert.ok(doc.includes('https://safetyvibe.eu/connect/source/0.3.3'));
  }
});

test('0.3.3 release metadata and published documentation agree', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.version, '0.3.3');
  assert.deepEqual(pkg.files, ['cli.mjs', 'lib.mjs', 'README.md', 'AGENTS.md', 'LICENSE', 'SECURITY.md']);
  for (const field of ['scripts', 'dependencies', 'devDependencies', 'optionalDependencies']) assert.equal(pkg[field], undefined);
  assert.deepEqual(pkg.repository, { type: 'git', url: 'git+https://github.com/kare22/safety-vibe-connector.git' });
  for (const file of ['README.md', 'AGENTS.md']) {
    const doc = readFileSync(new URL('../' + file, import.meta.url), 'utf8');
    assert.doesNotMatch(doc, /unreleased|safetyvibe-connect@0\.3\.1|source\/0\.3\.1/);
    for (const command of [
      'npx -y safetyvibe-connect@0.3.3 inventory --json --compact',
      'npx -y safetyvibe-connect@0.3.3 inventory --project frontend --json --compact',
      'pnpm dlx safetyvibe-connect@0.3.3 setup',
      'bunx safetyvibe-connect@0.3.3 setup',
      'yarn dlx safetyvibe-connect@0.3.3 setup',
    ]) assert.ok(doc.includes(command), command);
    assert.match(doc, /0\.3\.2 \(2026-10-19\) adds/);
    assert.match(doc, /--json=summary/);
    assert.match(doc, /Direct means safe registry declarations/);
    assert.match(doc, /Total means unique name\+resolved-version rows/);
    assert.match(doc, /Real `setup` refuses them with exit 1 before any network call/);
    assert.match(doc, /real `scan` emits the same warning and exits 0/);
    assert.match(doc, /explicit `--out` export is processed before the guard/);
    assert.match(doc, /a refused real run prints no JSON on stdout/);
  }
});

test('strict public keys and dotenv comments never leak', () => {
  const key = 'sb_publishable_abc123def456';
  for (const v of [key + ' sb_secret_xyz', 'sb_publishable_sb_secret_abc', SERVICE, jwt({ role: 'authenticated' }), jwt({}), ANON + ' # comment', key + ' ', 'SB_SECRET_xyz']) assert.equal(publicKeyKind(v), null);
  assert.equal(publicKeyKind(ANON), 'anon'); assert.equal(publicKeyKind(key), 'publishable');
  assert.equal(publicKeyKind('sb_publishable_abc'), null);
  const dir = mkdtempSync(join(tmpdir(), 'svkeys-'));
  for (const value of [key + ' # sb_secret_xyz789xyz789', '"' + key + '" # sb_secret_xyz', "'" + key + "' # sb_secret_xyz", '`' + key + '` # sb_secret_xyz']) {
    writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_URL=https://abc.supabase.co\nVITE_SUPABASE_PUBLISHABLE_KEY=' + value);
    assert.equal(findSupabase(dir, {}).key, key);
    assert.deepEqual(findSupabase(dir, {}).warnings, []);
    assert.doesNotMatch(JSON.stringify(buildReport(dir, {}, {})), /sb_secret/i);
  }
  assert.equal(parseEnv('export KEY=value#comment').KEY, 'value');
  assert.equal(parseEnv('KEY="unterminated').KEY, undefined);
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_ANON_KEY=' + SERVICE);
  assert.deepEqual(findSupabase(dir, {}).warnings, ['VITE_SUPABASE_ANON_KEY']);
  assert.equal(findSupabase(dir, {}).key, '');
  assert.equal(findSupabase(dir, { VITE_SUPABASE_ANON_KEY: key + ' # sb_secret_x' }).key, '');
});

test('generic sk_ keys and default-ignorable/combining characters are screened', async () => {
  const { secretLike } = await import('../lib.mjs');
  for (const v of ['sk_0123456789abcdef0123456789abcdef', 'prefix sk_0123456789abcdef0123', 'sb_͏secret_0123456789abcdef0123456789abcdef', 'sb_́secret_abc']) assert.equal(secretLike(v), true, JSON.stringify(v));
  assert.equal(secretLike('sk_0123456789abcdef0123456789abcdef', true), true);
  for (const v of ['sb_sécret_' + 'a'.repeat(32), 'SK_0123456789abcdef0123456789abcdef', 'sk_ा0123456789abcdef0123', 'Sb_Secret_abc']) assert.equal(secretLike(v, true), true, JSON.stringify(v));
  for (const v of ['honeyjar', 'task_runner', 'risk-assessment-tool', '@tanstack/react-query', 'class-variance-authority']) assert.equal(secretLike(v, true), false, v);
});
test('0.3.1 a non-anon JWT in a publishable/anon key slot stays a secret (no regression from strict literal rules)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'sv-slot-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'lib'));
  const env = { VITE_SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co' };
  const admin = jwt({ role: 'supabase_admin' });
  assert.equal(findSupabase(dir, { ...env, VITE_SUPABASE_ANON_KEY: admin }).warnings.length, 1, 'env slot');
  writeFileSync(join(dir, 'lib', 'supabase.ts'), 'const SUPABASE_ANON_KEY = "' + admin + '";');
  assert.equal(findSupabase(dir, env).warnings.length, 1, 'assignment slot');
  assert.equal(buildReport(dir, {}, env).supabase.secret_key_exposed_client_side, true);
  writeFileSync(join(dir, 'lib', 'supabase.ts'), 'const SUPABASE_ANON_KEY = "' + ANON + '";');
  assert.deepEqual(findSupabase(dir, env).warnings, [], 'anon stays public');
});
