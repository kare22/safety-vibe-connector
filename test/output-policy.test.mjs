import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { project, json, run } from './helpers.mjs';

const hints = ['REPLIT.*', 'REPL_ID', 'LOVABLE.*', 'BOLT.*', 'EMERGENT.*', 'BASE44_.*', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_ID', 'CONTINUOUS_INTEGRATION'];
const clean = Object.fromEntries(Object.keys(process.env)
  .filter(k => !/^(PATH|SYSTEMROOT|WINDIR|TEMP|TMP|TMPDIR|COMSPEC|PATHEXT)$/i.test(k)).map(k => [k, undefined]));
const tty = { ...clean, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent("Object.defineProperty(process.stdout, 'isTTY', { value: true });") };

test('environment-name detection is limited to builder platforms and CI', () => {
  const cli = readFileSync(new URL('../cli.mjs', import.meta.url), 'utf8');
  const names = /Object\.keys\(process\.env\)\.some\(k => \/\^\(([^)]+)\)\$\//.exec(cli)?.[1];
  assert.deepEqual(names?.split('|'), hints);
});

test('non-terminal sessions default to summary and explicit JSON still works', async t => {
  const root = project(t); json(root, 'package-lock.json', { packages: {} });
  const result = await run(root, ['inventory'], { ...clean, GENERIC_HOST_SESSION: '1' });
  assert.equal(result.code, 0); assert.match(result.stdout, /^Platform:/);
  const full = await run(root, ['inventory', '--json'], { ...clean, GENERIC_HOST_SESSION: '1' });
  assert.equal(full.code, 0); assert.equal(JSON.parse(full.stdout).v, 1);
});

test('terminal sessions honor builder and CI hints and explicit JSON', async t => {
  const root = project(t); json(root, 'package-lock.json', { packages: {} });
  const interactive = await run(root, ['inventory'], tty);
  assert.equal(JSON.parse(interactive.stdout).v, 1);
  for (const key of hints.map(value => value.replace('.*', '_SESSION'))) {
    const env = { ...tty, [key]: '1' };
    const summary = await run(root, ['inventory'], env);
    assert.equal(summary.code, 0); assert.match(summary.stdout, /^Platform:/);
    const full = await run(root, ['inventory', '--json'], env);
    assert.equal(full.code, 0); assert.equal(JSON.parse(full.stdout).v, 1);
  }
});
