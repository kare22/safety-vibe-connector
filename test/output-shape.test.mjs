import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildReport } from '../lib.mjs';

test('connector JSON uses only documented envelope fields and value types', t => {
  const dir = mkdtempSync(join(tmpdir(), 'connector-shape-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const write = (name, value) => writeFileSync(join(dir, name), JSON.stringify(value));
  const json = (options = {}, env = {}) => JSON.parse(JSON.stringify(buildReport(dir, options, env)));
  write('package.json', {});
  const declared = {
    v: 1, lockfile: 'none', versions_source: 'declared', source: 'connector',
    packages: [], supabase: null,
  };
  assert.deepEqual(json(), declared);

  write('package.json', { dependencies: { react: '^18.2.0' }, devDependencies: { vite: '~6.0.0' } });
  assert.deepEqual(json(), {
    ...declared,
    packages: [
      { ecosystem: 'npm', name: 'vite', version: '~6.0.0', dev: true },
      { ecosystem: 'npm', name: 'react', version: '^18.2.0' },
    ],
  });

  write('package-lock.json', { lockfileVersion: 3, packages: {
    'node_modules/react': { version: '18.3.1' },
    'node_modules/vite': { version: '6.0.0', dev: true },
  } });
  const resolved = {
    ...declared, lockfile: 'package-lock.json', versions_source: 'lockfile',
    packages: [
      { ecosystem: 'npm', name: 'react', version: '18.3.1' },
      { ecosystem: 'npm', name: 'vite', version: '6.0.0', dev: true },
    ],
  };
  assert.deepEqual(json(), resolved);

  const host = 'abcdefghijklmnopqrst.supabase.co';
  const key = 'sb_publishable_' + 'a1'.repeat(16);
  const env = { VITE_SUPABASE_URL: 'https://' + host, VITE_SUPABASE_PUBLISHABLE_KEY: key, VERCEL: '1' };
  const metadata = { name: 'Sample Notes', url: 'https://notes.example.com', environment: 'production' };
  assert.deepEqual(json(metadata, env), {
    ...resolved, ...metadata, platform: 'Vercel',
    supabase: {
      project_ref: 'abcdefghijklmnopqrst', host, key_kind: 'publishable',
      key_fingerprint: createHash('sha256').update(key).digest('hex').slice(0, 8),
    },
  });
  assert.deepEqual(json({}, { ...env, VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_secret_' + 'a1'.repeat(16) }), {
    ...resolved, platform: 'Vercel',
    supabase: { project_ref: 'abcdefghijklmnopqrst', host, secret_key_exposed_client_side: true },
  });

  write('package-lock.json', { lockfileVersion: 3, packages: {} });
  assert.deepEqual(json(), { ...resolved, packages: [] });
  write('package-lock.json', { lockfileVersion: 3, packages: Object.fromEntries(
    Array.from({ length: 5001 }, (_, i) => ['node_modules/fixture-' + i, { version: '1.0.0' }]),
  ) });
  assert.deepEqual(json(), {
    ...resolved, truncated: true,
    packages: Array.from({ length: 5000 }, (_, i) => ({ ecosystem: 'npm', name: 'fixture-' + i, version: '1.0.0' })),
  });
});
