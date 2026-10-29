import assert from 'node:assert/strict';

// Expected installation keys come from fixture data, independently of the
// parser's decision log. A missing log entry therefore cannot hide a lost row.
export function assertAccounted(rows, expected) {
  const decisions = rows.classifications || [];
  // Output identities must come only from reported decisions. Multiple Yarn
  // selectors may report the same identity, so compare sets.
  const reported = [...new Set(decisions.filter(d => d.status === 'reported').map(d => d.name + '@' + d.version))].sort();
  assert.deepEqual([...new Set(rows.map(row => row.name + '@' + row.version))].sort(), reported);
  assert.deepEqual(decisions.map(({ key, status, reason }) => ({ key, status, ...(reason ? { reason } : {}) })), expected.decisions);
  assert.deepEqual([...rows], expected.rows);
  assert.equal(!!rows.incomplete, expected.incomplete);
  for (const decision of decisions) {
    if (decision.status === 'reported') assert.ok(rows.some(row => row.name === decision.name && row.version === decision.version));
    else if (decision.status === 'excluded') assert.ok(['source protocol', 'git shorthand', 'declared URL dependency', 'known source-host archive', 'workspace link'].includes(decision.reason));
    else { assert.equal(decision.status, 'incomplete'); assert.equal(rows.incomplete, true); }
  }
  for (const row of rows) assert.ok(decisions.some(d => d.status === 'reported' && d.name === row.name && d.version === row.version));
}

export function assertFixtureAccounted(rows, fixture) {
  const input = fixture.args[0]; let keys;
  if (fixture.parser === 'fromPackageLock') {
    if (input.packages) keys = Object.keys(input.packages).filter(key => key.includes('node_modules/'));
    else {
      keys = [];
      const visit = (dependencies, parent = '') => { for (const [name, value] of Object.entries(dependencies || {})) {
        const key = parent + 'node_modules/' + name; keys.push(key); visit(value?.dependencies, key + '/');
      } };
      visit(input.dependencies);
    }
  } else if (fixture.parser === 'fromBunLock') keys = Object.keys(JSON.parse(input).packages);
  else if (fixture.parser === 'fromYarnLock') keys = input.split(/\r?\n/).filter(line => /^\S/.test(line) && !/^(#|__metadata:)/.test(line))
    .flatMap(line => [...new Set(line.replace(/:$/, '').split(/,\s*/).map(key => key.replace(/^"|"$/g, '')))]);
  else if (fixture.parser === 'fromPnpmLock') {
    const section = input.split(/^packages:\s*$/m)[1]?.split(/^\S/m)[0] || '';
    keys = section.split(/\r?\n/).filter(line => /^ {2}\S/.test(line)).map(line => line.trim().replace(/:$/, '').replace(/^['"]|['"]$/g, ''));
  } else assert.fail('Unknown fixture format');
  assert.deepEqual((rows.classifications || []).map(d => d.key), keys, 'every fixture installation must have a decision');
  assertAccounted(rows, fixture.expected);
}
