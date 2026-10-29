import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as lib from '../lib.mjs';
import { assertFixtureAccounted } from './source-accounting.mjs';
import { project, run, receiver } from './helpers.mjs';

const fixtures = JSON.parse(readFileSync(new URL('./fixtures/source-corpus.json', import.meta.url), 'utf8')).filter(f => f.round === 5);
for (const fixture of fixtures) test(fixture.label, async t => {
  assertFixtureAccounted(lib[fixture.parser](...fixture.args), fixture);
  const root = project(t, fixture.args[1]?.manifest || {});
  const pnpm = fixture.parser === 'fromPnpmLock';
  writeFileSync(join(root, pnpm ? 'pnpm-lock.yaml' : 'package-lock.json'), pnpm ? fixture.args[0] : JSON.stringify(fixture.args[0]));
  const report = lib.buildReport(root, {}, {});
  assert.deepEqual(report.packages, fixture.expected.rows.map(row => ({ ecosystem: 'npm', ...row })));
  assert.equal(!!report.incomplete, fixture.expected.incomplete);
  const server = await receiver(t);
  const result = await run(root, ['setup', '--no-hook'], server);
  assert.equal(result.code, fixture.expected.incomplete ? 1 : 0, result.stderr);
  assert.equal(server.hits.length, fixture.expected.incomplete ? 0 : 1);
  if (server.hits.length) assert.deepEqual(server.hits[0].packages, report.packages);
});
