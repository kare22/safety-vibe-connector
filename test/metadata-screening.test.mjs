import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secretLike, screenString, buildReport, takeScreenWarnings } from '../lib.mjs';
import { project, json, run, receiver } from './helpers.mjs';

for (const prefix of ['npm_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_', 'sk_live_']) {
  test('screens provider family before package exemptions: ' + prefix, () => {
    const token = prefix + 'a1'.repeat(20);
    const encoded = [...token].map(c => '%' + c.charCodeAt(0).toString(16)).join('');
    for (const value of [token, '@scope/' + token, '@' + token + '/package', encoded, token.replace('_', '\u200b_'), token.replace('p', '\u0440')]) {
      assert.ok(secretLike(value, true), 'provider shape must be screened');
      assert.ok(screenString(value, 'package name', () => {}, true) === '', 'screen must drop value');
    }
  });
}
test('retains long ordinary registry names', () => {
  for (const name of ['@scope/some-long-normal-package-name', 'a'.repeat(60), 'npm-package-name', 'github-pat-helper']) assert.equal(secretLike(name, true), false);
});
test('CLI drops token-shaped metadata and refuses a filtered incomplete inventory', async t => {
  const root = project(t); const server = await receiver(t); const token = 'npm_' + 'z9'.repeat(18);
  json(root, 'package-lock.json', { packages: { ['node_modules/' + token]: { version: '1.0.0' } } });
  const body = buildReport(root, {}, {});
  assert.ok(!JSON.stringify(body).includes(token)); assert.equal(body.incomplete, true);
  takeScreenWarnings();
  const result = await run(root, ['setup', '--json', '--no-hook'], server);
  assert.equal(result.code, 1); assert.equal(server.hits.length, 0);
  assert.ok(!JSON.stringify(result).includes(token)); assert.match(result.stderr, /Dropped package name/);
});
