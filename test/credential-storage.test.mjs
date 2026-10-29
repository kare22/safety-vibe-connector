import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { project, json, run, receiver } from './helpers.mjs';

test('an env-keyed linked scan neither verifies Git nor writes connection settings', async t => {
  const root = project(t); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  json(root, '.safetyviberc.json', { site: '12345678-1234-1234-1234-123456789abc', hook: false });
  const snapshot = () => Object.fromEntries(readdirSync(root).sort().map(file => [file, readFileSync(join(root, file), 'utf8')]));
  const before = snapshot();
  const preload = `import cp from 'node:child_process'; import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
    cp.spawnSync = () => { throw new Error('Git must not be called for an env-only scan'); };
    fs.writeFileSync = () => { throw new Error('env-only scan must not write'); };
    fs.unlinkSync = () => { throw new Error('env-only scan must not remove config'); };
    syncBuiltinESMExports();`;
  const result = await run(root, ['scan'], { ...server, SAFETYVIBE_KEY: 'svk_' + 'b'.repeat(32),
    NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /Connected:/);
  assert.equal(result.stderr, '');
  assert.equal(server.hits.length, 1);
  assert.deepEqual(snapshot(), before);
});

for (const [status, body, warning] of [[403, '{"error":"fixture rejection"}', /report rejected/], [200, 'not-json', /unexpected response/],
  [200, '[]', /unexpected response/]]) {
  test(`an env-keyed scan stays read-only on receiver status ${status} and body ${body}`, async t => {
    const root = project(t); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    json(root, '.safetyviberc.json', { site: '12345678-1234-1234-1234-123456789abc', hook: false });
    const snapshot = () => Object.fromEntries(readdirSync(root).sort().map(file => [file, readFileSync(join(root, file), 'utf8')]));
    const before = snapshot();
    const preload = `import cp from 'node:child_process'; import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
      cp.spawnSync = () => { throw new Error('unexpected Git preflight'); };
      fs.writeFileSync = fs.unlinkSync = () => { throw new Error('unexpected config mutation'); };
      syncBuiltinESMExports();
      const send = globalThis.fetch;
      globalThis.fetch = async (...args) => { await send(...args); return new Response(${JSON.stringify(body)}, { status: ${status} }); };`;
    const result = await run(root, ['scan'], { ...server, SAFETYVIBE_KEY: 'svk_' + 'b'.repeat(32),
      NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
    assert.equal(result.code, 0);
    assert.match(result.stderr, warning);
    assert.doesNotMatch(result.stdout + result.stderr, /Connected:|svk_|unexpected Git|unexpected config/);
    assert.equal(server.hits.length, 1);
    assert.deepEqual(snapshot(), before);
  });
}

for (const mode of ['stored key', 'stored claim', 'legacy config', 'changed URL', 'changed name', 'hook preference']) {
  test(`an env-keyed scan keeps credential preflight for ${mode}`, async t => {
    const root = project(t); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    json(root, '.safetyviberc.json', { site: '12345678-1234-1234-1234-123456789abc',
      ...(mode === 'legacy config' ? { api: 'https://obsolete.example' } : {}) });
    if (mode === 'stored key') json(root, '.safetyviberc.local.json', { key: 'svk_' + 'b'.repeat(32) });
    if (mode === 'stored claim') json(root, '.safetyviberc.local.json', { claimToken: 'a'.repeat(24) });
    const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
      cp.spawnSync = () => ({ status: 128, stdout: '', stderr: 'fatal: detected dubious ownership in repository' });
      syncBuiltinESMExports();`;
    const args = { 'changed URL': ['--url', 'https://notes.example'], 'changed name': ['--name', 'notes'], 'hook preference': ['--no-hook'] }[mode] || [];
    const result = await run(root, ['scan', ...args], { ...server, SAFETYVIBE_KEY: 'svk_' + 'b'.repeat(32),
      NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
    assert.equal(result.code, 0);
    assert.equal(server.hits.length, 0);
    assert.match(result.stderr, /could not verify effective Git ignoring/i);
  });
}

function git(root, args) { return execFileSync('git', ['-C', root, ...args], { windowsHide: true, stdio: 'pipe' }).toString().trim(); }
test('a three-second Git cold start still permits verified credential storage', async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    const original = cp.spawnSync; let delayed = false;
    cp.spawnSync = (file, args, options) => {
      if (file === 'git') {
        if (options.timeout !== 15000 || options.shell) throw new Error('unexpected execution policy');
        if (!delayed) {
          delayed = true;
          const delay = original(process.execPath, ['-e', 'setTimeout(() => {}, 3000)'],
            { ...options, env: { ...options.env, NODE_OPTIONS: '' } });
          if (delay.error || delay.signal || delay.status !== 0) return delay;
        }
      }
      return original(file, args, options);
    }; syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook'], { ...server,
    NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(server.hits.length, 1);
  assert.equal(JSON.parse(readFileSync(join(root, '.safetyviberc.local.json'), 'utf8')).key, 'svk_' + 'a'.repeat(32));
  assert.equal(spawnSync('git', ['-C', root, 'check-ignore', '--no-index', '--quiet', '--', '.safetyviberc.local.json']).status, 0);
});

for (const command of ['rev-parse', 'ls-files', 'check-ignore']) {
  test(`a hung Git ${command} fails closed before reporting or saving credentials`, async t => {
    const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
      const original = cp.spawnSync;
      cp.spawnSync = (file, args, options) => {
        if (file === 'git') {
          if (options.timeout !== 15000 || options.shell) throw new Error('unexpected execution policy');
          if (args.includes(${JSON.stringify(command)})) {
            const result = original(process.execPath, ['-e', 'setInterval(() => {}, 1000)'],
              { ...options, timeout: 100, env: { ...options.env, NODE_OPTIONS: '' } });
            if (result.error?.code !== 'ETIMEDOUT') throw new Error('expected real subprocess timeout');
            process.stderr.write('fixture subprocess timed out\\n');
            return result;
          }
        }
        return original(file, args, options);
      }; syncBuiltinESMExports();`;
    const result = await run(root, ['setup', '--no-hook'], { ...server,
      NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /fixture subprocess timed out/);
    assert.match(result.stderr, /could not verify/i);
    assert.equal(server.hits.length, 0);
    assert.equal(existsSync(join(root, '.safetyviberc.local.json')), false);
    assert.equal(existsSync(join(root, '.safetyviberc.json')), false);
  });
}

for (const rules of ['.safetyviberc.local.json\n!*.json\n', '# .safetyviberc.local.json\n!*.json\n']) {
  test('final ignore is effective after negations', async t => {
    const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
    json(root, 'package-lock.json', { packages: {} });
    writeFileSync(join(root, '.gitignore'), rules);
    const result = await run(root, ['setup', '--no-hook'], server);
    assert.equal(result.code, 0);
    assert.equal(spawnSync('git', ['-C', root, 'check-ignore', '--no-index', '--quiet', '--', '.safetyviberc.local.json']).status, 0);
    assert.equal(git(root, ['ls-files', '--others', '--exclude-standard']).includes('.safetyviberc.local.json'), false);
    const ignore = readFileSync(join(root, '.gitignore'), 'utf8');
    assert.equal((await run(root, ['setup', '--no-hook'], server)).code, 0);
    assert.equal(readFileSync(join(root, '.gitignore'), 'utf8'), ignore);
  });
}
test('tracked credentials always warn with explicit removal and rotation guidance', async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  json(root, '.safetyviberc.local.json', {}); git(root, ['add', '--', '.safetyviberc.local.json']);
  const result = await run(root, ['setup', '--no-hook', '--quiet'], server);
  assert.match(result.stderr, /already tracked/i); assert.match(result.stderr, /git rm --cached/); assert.match(result.stderr, /rotate/i);
  assert.equal(git(root, ['ls-files', '--', '.safetyviberc.local.json']), '.safetyviberc.local.json');
  assert.equal(result.code, 1);
  assert.equal(server.hits.length, 0);
  assert.equal(readFileSync(join(root, '.safetyviberc.local.json'), 'utf8'), '{}');
  assert.doesNotMatch(result.stderr, /svk_[a-z0-9_-]{32}/i);
});

test('Git repository errors cannot count as a verified ignore', async t => {
  const root = project(t); const server = await receiver(t); json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    cp.spawnSync = () => ({ status: 128, stdout: '', stderr: 'fatal: detected dubious ownership in repository' });
    syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook'], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1); assert.match(result.stderr, /could not verify effective Git ignoring/i);
  assert.equal(server.hits.length, 0);
  assert.equal(existsSync(join(root, '.safetyviberc.local.json')), false);
});

for (const failure of [
  { status: 128, stdout: '', stderr: 'fatal: index unreadable' },
  { status: null, signal: null, stdout: '', stderr: '' },
  { status: null, signal: 'SIGTERM', error: { code: 'ETIMEDOUT' }, stdout: '', stderr: '' },
  { status: 1, signal: 'SIGTERM', stdout: '', stderr: '' },
  { status: 1, error: { code: 'EACCES' }, stdout: '', stderr: '' },
  { status: 2, stdout: '', stderr: 'unexpected status' },
]) for (const existing of [false, true]) test(`credential writes stop when only tracked-file verification fails: ${JSON.stringify(failure)}, existing=${existing}`, async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const publicConfig = { site: '12345678-1234-1234-1234-123456789abc', hook: false };
  json(root, '.safetyviberc.json', publicConfig);
  writeFileSync(join(root, '.gitignore'), '/.safetyviberc.local.json\n');
  const oldCredentials = JSON.stringify({ key: 'svk_' + 'b'.repeat(32) });
  if (existing) {
    writeFileSync(join(root, '.safetyviberc.local.json'), oldCredentials);
    git(root, ['add', '--force', '--', '.safetyviberc.local.json']);
  }
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    const original = cp.spawnSync;
    cp.spawnSync = (file, args, options) => {
      if (args.includes('ls-files')) {
        if (options.timeout !== 15000 || options.shell) throw new Error('unexpected execution policy');
        return ${JSON.stringify(failure)};
      }
      return original(file, args, options);
    };
    syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook', '--quiet'], { ...server, SAFETYVIBE_KEY: 'svk_' + 'b'.repeat(32), NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1);
  assert.equal(server.hits.length, 0);
  assert.match(result.stderr, /could not verify.*tracked/i);
  assert.match(result.stderr, /no credentials saved/i);
  assert.doesNotMatch(result.stderr, /svk_[a-z0-9_-]{32}/i);
  assert.equal(existsSync(join(root, '.safetyviberc.local.json')), existing);
  if (existing) assert.equal(readFileSync(join(root, '.safetyviberc.local.json'), 'utf8'), oldCredentials);
  assert.deepEqual(JSON.parse(readFileSync(join(root, '.safetyviberc.json'), 'utf8')), publicConfig);
});

test('an absent Git binary permits unversioned setup and adds the anchored ignore rule', async t => {
  const root = project(t); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    cp.spawnSync = () => ({ status: null, signal: null, error: { code: 'ENOENT' }, stdout: '', stderr: '' });
    syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook'], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(join(root, '.safetyviberc.local.json'), 'utf8')).key, 'svk_' + 'a'.repeat(32));
  assert.equal(readFileSync(join(root, '.gitignore'), 'utf8'), '/.safetyviberc.local.json\n');
  assert.doesNotMatch(result.stderr, /could not verify/i);
});

test('every Git subprocess uses the C locale before reporting and when saving', async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    const original = cp.spawnSync; const calls = new Set();
    cp.spawnSync = (file, args, options) => {
      if (file === 'git') {
        if (options.env?.LC_ALL !== 'C' || options.env?.LANGUAGE !== 'C' || !options.env?.PATH) throw new Error('wrong Git environment');
        calls.add(args[2]);
      }
      return original(file, args, options);
    }; syncBuiltinESMExports();
    const fetchReport = globalThis.fetch;
    globalThis.fetch = (...args) => {
      if (!['rev-parse', 'ls-files', 'check-ignore'].every(command => calls.has(command))) throw new Error('Git checks ran too late');
      return fetchReport(...args);
    };`;
  const result = await run(root, ['setup', '--no-hook'], { ...server, LC_ALL: 'de_DE.UTF-8', LANGUAGE: 'de', NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(server.hits.length, 1);
});

test('an ineffective ignore refuses a new claim before reporting', async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    const original = cp.spawnSync;
    cp.spawnSync = (file, args, options) => args.includes('check-ignore') ? { status: 1 } : original(file, args, options);
    syncBuiltinESMExports();`;
  const result = await run(root, ['setup', '--no-hook', '--claim-token', 'a'.repeat(24)], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1);
  assert.equal(server.hits.length, 0);
  assert.match(result.stderr, /nothing sent/);
  assert.equal(existsSync(join(root, '.safetyviberc.local.json')), false);
});

test('a credential safety change after acceptance prints site recovery guidance without a key', async t => {
  const root = project(t); git(root, ['init', '--quiet']); const server = await receiver(t);
  json(root, 'package-lock.json', { packages: {} });
  const preload = `import cp from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';
    const original = cp.spawnSync; let accepted = false;
    cp.spawnSync = (file, args, options) => accepted && args.includes('ls-files') ? { status: 0 } : original(file, args, options);
    syncBuiltinESMExports();
    const fetchReport = globalThis.fetch;
    globalThis.fetch = async (...args) => { const response = await fetchReport(...args); accepted = true; return response; };`;
  const result = await run(root, ['setup', '--quiet'], { ...server, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1);
  assert.equal(server.hits.length, 1);
  assert.match(result.stderr, /app id 12345678-1234-1234-1234-123456789abc/);
  assert.match(result.stderr, /run setup in a writable checkout/);
  assert.doesNotMatch(result.stdout + result.stderr, /svk_[a-z0-9_-]{32}/i);
  assert.equal(existsSync(join(root, '.safetyviberc.local.json')), false);
  assert.equal(existsSync(join(root, '.safetyviberc.json')), false);
  assert.equal(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts, undefined);
});
