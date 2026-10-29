import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';
import { project } from './helpers.mjs';

for (const [label, filename, text] of [
  ['npm invalid resolved registry version', 'package-lock.json', JSON.stringify({ packages: {
    'node_modules/lodash': { version: 'not a version', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' },
  } })],
  ['pnpm missing registry integrity', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {}\n"],
  ['Yarn Berry missing registry resolution', 'yarn.lock', '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n'],
  ['Bun malformed package tuple', 'bun.lock', '{"packages":{"lodash":[]}}'],
  ['Bun missing registry field', 'bun.lock', '{"packages":{"lodash":["lodash@4.17.20"]}}'],
  ['Bun invalid registry field', 'bun.lock', '{"packages":{"lodash":["lodash@4.17.20",{}]}}'],
  ['npm invalid resolved field', 'package-lock.json', JSON.stringify({ packages: {
    'node_modules/lodash': { version: '4.17.20', resolved: {} },
  } })],
  ['Yarn Berry malformed registry resolution', 'yarn.lock', '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n  resolution: "not-a-resolution"\n'],
]) test('' + label + ' is incomplete', t => {
  const root = project(t); writeFileSync(join(root, filename), text);
  const report = buildReport(root, {}, {});
  assert.equal(report.incomplete, true);
});
