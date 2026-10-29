import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, linkSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport, readPackages, selectProject } from '../lib.mjs';
import { project, json, run, receiver } from './helpers.mjs';

const directoryLink = (target, path) => symlinkSync(target, path, process.platform === 'win32' ? 'junction' : 'dir');
for (const dir of ['src', 'frontend']) test('refuses read through an escaping directory: ' + dir, async t => {
  const root = project(t); const outside = project(t); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  mkdirSync(join(outside, 'lib'));
  writeFileSync(join(outside, 'lib/supabase.ts'), 'const secret = "sb_secret_' + 'q9'.repeat(20) + '";');
  writeFileSync(join(outside, '.env'), 'URL=https://fixture.emergent.host');
  directoryLink(outside, join(root, dir));
  assert.throws(() => buildReport(root, {}, {}), /boundary|outside|linked/i);
  const result = await run(root, ['setup', '--no-hook'], server);
  assert.equal(result.code, 1); assert.equal(server.hits.length, 0);
  assert.match(result.stderr, /boundary|outside|linked/i);
});

for (const file of ['.safetyviberc.json', '.safetyviberc.local.json', '.gitignore', 'package.json']) {
  test('refuses linked config target before requests: ' + file, async t => {
    const root = project(t); const outside = project(t); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    const target = join(outside, 'target'); writeFileSync(target, '{}');
    if (file === 'package.json') {
      // A second hard link models a writable file shared outside the selected project.
      linkSync(join(root, file), join(outside, 'manifest'));
    } else linkSync(target, join(root, file));
    const before = readFileSync(target, 'utf8');
    const result = await run(root, ['setup'], server);
    assert.equal(result.code, 1); assert.equal(server.hits.length, 0);
    assert.equal(readFileSync(target, 'utf8'), before);
    assert.match(result.stderr, /boundary|outside|linked/i);
  });
}

for (const file of ['.safetyviberc.json', '.safetyviberc.local.json', '.gitignore', 'package.json']) {
  test('refuses even an internal config symlink: ' + file, async t => {
    const root = project(t); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    if (file !== 'package.json') writeFileSync(join(root, file), '{}');
    const preload = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
      const lstat = fs.lstatSync;
      fs.lstatSync = (path, ...args) => {
        const info = lstat(path, ...args);
        if (String(path).endsWith(${JSON.stringify(file)})) info.isSymbolicLink = () => true;
        return info;
      }; syncBuiltinESMExports();`;
    const result = await run(root, ['setup'], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
    assert.equal(result.code, 1); assert.equal(server.hits.length, 0);
    assert.match(result.stderr, /boundary|outside|linked/i);
  });
}

test('reads may follow directory links that remain inside the project', t => {
  const root = project(t); const client = join(root, 'client'); mkdirSync(join(client, 'lib'), { recursive: true });
  writeFileSync(join(client, 'lib/supabase.ts'), 'const secret = "sb_secret_' + 'q9'.repeat(20) + '";');
  directoryLink(client, join(root, 'src'));
  assert.equal(buildReport(root, {}, {}).supabase.secret_key_exposed_client_side, true);
});

test('bounded lock reads reject a lockfile directory junction', t => {
  const root = project(t); const outside = project(t);
  mkdirSync(join(root, 'apps')); directoryLink(outside, join(root, 'apps', 'web'));
  assert.throws(() => selectProject(root, 'apps/web'));
});

test('intentional workspace ancestor lock remains readable', t => {
  const root = project(t, { workspaces: ['apps/*'] }); const child = join(root, 'apps/web');
  mkdirSync(child, { recursive: true }); json(child, 'package.json', {});
  json(root, 'package-lock.json', { packages: { 'node_modules/fixture': { version: '1.0.0' } } });
  assert.equal(readPackages(child).packages[0].name, 'fixture');
});

test('refuses escaped file reads even when the file looks like valid registry metadata', async t => {
  const root = project(t); const outside = project(t); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  // Model file symlinks on platforms where creating them needs extra OS privileges.
  const preload = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
    const realpath = fs.realpathSync;
    fs.realpathSync = (path, ...args) => String(path).endsWith('package-lock.json') ? ${JSON.stringify(join(outside, 'package.json'))} : realpath(path, ...args);
    syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook'], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1); assert.equal(server.hits.length, 0);
  assert.match(result.stderr, /boundary|outside|linked/i);
});
