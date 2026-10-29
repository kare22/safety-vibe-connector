import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromYarnLock, buildReport } from '../lib.mjs';
import { project } from './helpers.mjs';

for (const berry of [false, true]) for (const alias of ['compat', '@local/compat']) for (const name of ['lodash', '@registry/real']) {
  test(`${berry ? 'Berry' : 'v1'} ${alias} uses registry identity ${name}`, t => {
    const selector = alias + '@npm:' + name + '@^4.0.0';
    const lock = berry ? `__metadata:\n  version: 6\n\n"${selector}":\n  version: 4.17.20\n  resolution: "${name}@npm:4.17.20"\n`
      : `# yarn lockfile v1\n\n"${selector}":\n  version "4.17.20"\n`;
    const rows = fromYarnLock(lock, { devDependencies: { [alias]: 'npm:' + name + '@^4.0.0' } });
    assert.equal(rows[0].name, name); assert.equal(rows[0].version, '4.17.20');
    if (!berry) assert.equal(rows[0].dev, true);
    const root = project(t); writeFileSync(join(root, 'yarn.lock'), lock);
    assert.equal(buildReport(root, {}, {}).packages[0].name, name);
  });
}

test('aliases keep v1 selector reachability when deduplicated with runtime identity', () => {
  const lock = '"compat@npm:lodash@^4.0.0":\n  version "4.17.20"\n\nlodash@^4.0.0:\n  version "4.17.20"\n';
  assert.deepEqual(fromYarnLock(lock, { dependencies: { lodash: '^4.0.0' }, devDependencies: { compat: 'npm:lodash@^4.0.0' } }), [{ name: 'lodash', version: '4.17.20' }]);
});
