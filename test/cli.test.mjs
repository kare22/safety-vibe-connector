import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, rmSync, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
const CLI = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const KEY = 'svk_' + 'a'.repeat(32);
const SITE = '12345678-1234-1234-1234-123456789abc';
const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;

test('setup without a hook remains reportable by manual scan', async t => {
  const dir = project(t); const s = await server(t);
  assert.equal((await run(dir, ['setup', '--no-hook'], s.api)).code, 0);
  assert.equal((await run(dir, ['scan'], s.api)).code, 0);
  assert.equal(s.hits.length, 2); assert.equal(s.hits[1].headers['x-safetyvibe-site'], SITE);
  assert.equal(s.hits[1].headers['x-safetyvibe-key'], KEY);
});

for (const workspace of ['npm', 'pnpm']) test('installed workspace root never captures a child hook: ' + workspace, async t => {
  const root = project(t); const child = project(t); const s = await server(t);
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'monorepo', ...(workspace === 'npm' ? { workspaces: ['apps/*'] } : {}), dependencies: { 'safetyvibe-connect': '^0.2.2' } }));
  if (workspace === 'pnpm') writeFileSync(join(root, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
  writeFileSync(join(child, 'package.json'), JSON.stringify({ name: 'child', dependencies: { 'safetyvibe-connect': '^0.2.2' } }));
  const before = snapshot(root);
  assert.equal((await run(child, ['scan'], s.api, { INIT_CWD: root })).code, 0);
  assert.equal(s.hits[0].body.name, 'child'); assert.deepEqual(snapshot(root), before);
  assert.equal((await run(root, ['scan'], s.api)).code, 0);
  assert.equal(s.hits.length, 1); assert.deepEqual(snapshot(root), before);
});

test('0.2.2: pnpm-workspace.yaml without packages (pnpm 10 build settings) is a normal app', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'notes', devDependencies: { 'safetyvibe-connect': '^0.2.2' } }));
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'onlyBuiltDependencies:\n  - esbuild\n');
  assert.equal((await run(dir, ['scan'], s.api)).code, 0);
  assert.equal(s.hits.length, 1);
});

test('0.2.2: a workspace root that was deliberately linked keeps reporting', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'monorepo', workspaces: ['apps/*'] }));
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ site: SITE }));
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ key: KEY }));
  assert.equal((await run(dir, ['scan'], s.api)).code, 0);
  assert.equal(s.hits.length, 1); assert.equal(s.hits[0].headers['x-safetyvibe-site'], SITE);
  assert.equal(JSON.parse(readFileSync(join(dir, '.safetyviberc.json'), 'utf8')).site, SITE);   // documented: a linked root updates its rc
});

test('arbitrary rc site strings never leave through request headers', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ site: 'sb_secret_private-folder', key: KEY }));
  assert.equal((await run(dir, ['scan'], s.api)).code, 0);
  assert.equal(s.hits[0].headers['x-safetyvibe-site'], undefined);
  assert.doesNotMatch(JSON.stringify(s.hits), /sb_secret_private-folder/);
});

for (const mode of ['invalid-json', 'redirect', 'dns-failure', 'late-rejection']) test('scan exits zero promptly after ' + mode, async t => {
  const dir = project(t); const s = await server(t, (req, res) => {
    if (mode === 'redirect') { res.statusCode = 302; res.setHeader('location', '/redirect-target'); }
    return 'not json';
  });
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ claimToken: 'valid-claim-token' }));
  writeFileSync(join(dir, '.gitignore'), '/.safetyviberc.local.json\n');
  const before = snapshot(dir);
  // Simulate resolver failure without issuing any DNS request.
  const preload = mode === 'dns-failure' ? "globalThis.fetch = async () => { throw Object.assign(new Error('DNS'), { code: 'ENOTFOUND' }); };"
    : mode === 'late-rejection' ? "globalThis.fetch = () => new Promise((_, reject) => setTimeout(() => reject(new Error('late')), 5000));" : '';
  const start = Date.now();
  const result = await run(dir, ['scan'], s.api, { SAFETYVIBE_TIMEOUT_MS: '250', ...(preload ? { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) } : {}) });
  assert.equal(result.code, 0); assert.ok(Date.now() - start < 3000); assert.deepEqual(snapshot(dir), before);
  assert.equal(s.hits.length, preload ? 0 : 1);
});
function project(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sv-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'notes', scripts: { postinstall: 'node a.js' } }));
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_URL=https://abc.supabase.co\nVITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_abc123def456 # sb_secret_xyz789xyz789');
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/a': { version: '1.0.0', dev: true } } }));
  return dir;
}
const snapshot = dir => Object.fromEntries(readdirSync(dir).sort().map(f => [f, readFileSync(join(dir, f)).toString('base64')]));
async function server(t, responder = () => ({ site: SITE, key: KEY, claimed: true })) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    let text = ''; req.on('data', d => { text += d; }); req.on('end', () => {
      hits.push({ raw: text, body: JSON.parse(text), headers: req.headers });
      const b = responder(req, res); res.end(typeof b === 'string' ? b : JSON.stringify(b));
    });
  });
  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => srv.close(resolve)));
  return { hits, api: 'http://127.0.0.1:' + srv.address().port + '/connect/api/v1' };
}
function run(dir, args, api, extra = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, INIT_CWD: dir, SAFETYVIBE_API: api, ...extra };
    for (const k of Object.keys(env)) if (/SUPABASE|^SAFETYVIBE_(KEY|URL|CLAIM_TOKEN|ENV)$/.test(k)) delete env[k];
    Object.assign(env, extra);
    if (!env.SAFETYVIBE_API) env.SAFETYVIBE_API = 'http://127.0.0.1:9';
    const capture = mkdtempSync(join(tmpdir(), 'sv-output-'));
    const out = join(capture, 'stdout'); const err = join(capture, 'stderr');
    const outFd = openSync(out, 'w'); const errFd = openSync(err, 'w');
    const child = spawn(process.execPath, [CLI, ...args], { cwd: dir, env, stdio: ['ignore', outFd, errFd] });
    const watchdog = setTimeout(() => child.kill(), 13000);
    closeSync(outFd); closeSync(errFd);
    child.on('error', error => { clearTimeout(watchdog); reject(error); }); child.on('close', code => {
      clearTimeout(watchdog);
      const stdout = readFileSync(out, 'utf8'); const stderr = readFileSync(err, 'utf8');
      rmSync(capture, { recursive: true, force: true }); resolve({ code, stdout, stderr });
    });
  });
}
for (const [args, expected] of [[['--help'], 0], [['-h'], 0], [['help'], 0], [[], 0], [['--version'], 0], [['-v'], 0], [['--bogus'], 2], [['frobnicate'], 2], [['setup', '--bogus'], 2], [['setup', '--claim-token'], 2], [['setup', '--url='], 2], [['scan', '--bogus', '--quiet'], 0]]) {
  test('CLI inert arguments: ' + JSON.stringify(args), async t => {
    const dir = project(t); const before = snapshot(dir); const s = await server(t);
    const result = await run(dir, args, s.api);
    assert.equal(result.code, expected, result.stderr); assert.equal(s.hits.length, 0); assert.deepEqual(snapshot(dir), before);
    if (args.includes('--version') || args.includes('-v')) assert.equal(result.stdout.trim(), version);
  });
}
test('dry-run matches sent JSON; no-hook persists; URLs and names are normalized', async t => {
  const dir = project(t); const s = await server(t); const before = snapshot(dir);
  const args = ['setup', '--no-hook', '--url=https://user:pass@my.app/x?token=abc', '--name', 'My Notes'];
  const dry = await run(dir, [...args, '--dry-run', '--json'], s.api);
  assert.equal(dry.code, 0); assert.equal(s.hits.length, 0); assert.deepEqual(snapshot(dir), before);
  assert.equal(dry.stderr.trim().split('\n').length, 9); assert.match(dry.stderr, /content-type/);
  assert.equal(dry.stderr.split('\n')[0], 'Platform: unknown');
  assert.equal(dry.stderr.split('\n')[4], 'Dry run: nothing sent');
  const real = await run(dir, args, s.api); assert.equal(real.code, 0, real.stderr);
  assert.deepEqual(JSON.parse(dry.stdout), s.hits[0].body); assert.equal(s.hits[0].headers['user-agent'], 'safetyvibe-connect/' + version);
  assert.doesNotMatch(JSON.stringify(s.hits[0].body), /pass|token|sb_secret/);
  assert.match(real.stderr, /Removed credentials\/query/);
  const rc = JSON.parse(readFileSync(join(dir, '.safetyviberc.json'))); assert.equal(rc.url, 'https://my.app/x'); assert.equal(rc.name, 'My Notes'); assert.equal(rc.hook, false);
  assert.equal(snapshot(dir)['package.json'], before['package.json']);
  assert.equal(real.stdout.split('\n')[4], 'Connected: https://dashboard.safetyvibe.eu');
  await run(dir, ['setup'], s.api); assert.equal(snapshot(dir)['package.json'], before['package.json']);
});
test('committed API ignored and existing URL normalized again', async t => {
  const dir = project(t); const good = await server(t); const attacker = await server(t);
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ api: attacker.api, site: SITE, url: 'https://user:pass@my.app/x?token=abc' }));
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ key: KEY }));
  assert.equal((await run(dir, ['setup', '--no-hook'], good.api)).code, 0);
  assert.equal(attacker.hits.length, 0); assert.equal(good.hits.length, 1);
  const rc = JSON.parse(readFileSync(join(dir, '.safetyviberc.json'))); assert.equal(rc.api, undefined); assert.equal(rc.url, 'https://my.app/x');
});
test('remote HTTP endpoint rejected without writes', async t => {
  const dir = project(t); const before = snapshot(dir);
  assert.equal((await run(dir, ['setup'], 'http://example.com')).code, 1); assert.deepEqual(snapshot(dir), before);
});
for (const response of ['<html>ok</html>', '', {}, [], { site: 'junk' }]) test('invalid success response saves nothing: ' + JSON.stringify(response), async t => {
  const dir = project(t); writeFileSync(join(dir, '.gitignore'), '/.safetyviberc.local.json\n');
  const before = snapshot(dir); const s = await server(t, () => response);
  const result = await run(dir, ['setup'], s.api); assert.equal(result.code, 1); assert.match(result.stderr, /unexpected response from .* \(HTTP 200\)/); assert.deepEqual(snapshot(dir), before);
});
for (const code of ['claim_expired', 'claim_used']) test(code + ' removes committed token', async t => {
  const dir = project(t); const s = await server(t, (req, res) => { res.statusCode = 401; return { code }; });
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ claimToken: 'expired-claim-token' }));
  const result = await run(dir, ['setup'], s.api); assert.equal(result.code, 1); assert.match(result.stderr, /Get a new prompt/);
  assert.equal(JSON.parse(readFileSync(join(dir, '.safetyviberc.json'))).claimToken, undefined);
  await run(dir, ['setup'], s.api); assert.equal(s.hits[1].headers['x-safetyvibe-claim-token'], undefined);
});
test('failed config write is honest and does not add hook', async t => {
  const dir = project(t); const s = await server(t); const pkg = readFileSync(join(dir, 'package.json'), 'utf8'); mkdirSync(join(dir, '.safetyviberc.json'));
  const result = await run(dir, ['setup'], s.api); assert.equal(result.code, 1); assert.match(result.stderr, /config is not writable.*nothing sent/); assert.doesNotMatch(result.stdout, /linked|added/); assert.equal(s.hits.length, 0); assert.doesNotMatch(result.stderr, /[^\x00-\x7F]/);
  assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), pkg);
  assert.equal((await run(dir, ['scan'], s.api)).code, 0);
});
test('monorepo CLI reports parent lock but saves in child', async t => {
  const root = project(t); writeFileSync(join(root, 'package.json'), JSON.stringify({ workspaces: ['packages/*'] })); const s = await server(t); const child = join(root, 'packages', 'web'); mkdirSync(child, { recursive: true }); writeFileSync(join(child, 'package.json'), '{"name":"web"}');
  const result = await run(child, ['setup', '--no-hook'], s.api); assert.equal(result.code, 0); assert.equal(s.hits[0].body.packages[0].name, 'a'); assert.equal(s.hits[0].body.lockfile, 'package-lock.json');
  assert.equal(JSON.parse(readFileSync(join(child, '.safetyviberc.json'))).site, SITE);
});

for (const args of [['--claim-token', '-AbCdEfGhIjKlMnOpQrStUvWx'], ['--claim-token=-AbCdEfGhIjKlMnOpQrStUvWx']]) test('leading-dash claim token reaches server: ' + args.length, async t => {
  const dir = project(t); const s = await server(t);
  assert.equal((await run(dir, ['setup', '--no-hook', ...args], s.api)).code, 0);
  assert.equal(s.hits[0].headers['x-safetyvibe-claim-token'], '-AbCdEfGhIjKlMnOpQrStUvWx');
});
for (const flag of ['--dry-run', '--json', '--quiet', '--no-hook', '--help', '-h', '--version', '-v', '--claim-token', '--url', '--name', '--summary', '--out']) test('value flags reject known next flag: ' + flag, async t => {
  const dir = project(t); const s = await server(t);
  for (const valueFlag of ['--claim-token', '--url', '--name', '--out']) for (const next of [flag, flag + '=value']) {
    const result = await run(dir, ['setup', valueFlag, next], s.api);
    assert.equal(result.code, 2); assert.match(result.stderr, /Missing value/);
  }
  assert.equal(s.hits.length, 0);
});
test('secret public variable wins over anon key without leaking', async t => {
  const dir = project(t); const s = await server(t);
  const anon = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from('{"role":"anon"}').toString('base64url') + '.sig';
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_URL=https://abc.supabase.co\nVITE_SUPABASE_PUBLISHABLE_KEY=sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\nVITE_SUPABASE_ANON_KEY=' + anon);
  const result = await run(dir, ['setup', '--no-hook'], s.api);
  assert.equal(result.code, 0); assert.deepEqual(s.hits[0].body.supabase, { project_ref: null, host: 'abc.supabase.co', secret_key_exposed_client_side: true });
  assert.match(result.stderr, /VITE_SUPABASE_PUBLISHABLE_KEY holds a Supabase secret\/service_role key/);
  assert.doesNotMatch(result.stdout + result.stderr + JSON.stringify(s.hits), /sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1/);
});

for (const source of ['local', 'legacy', 'env']) test('report keys validated from ' + source, async t => {
  for (const valid of [false, true]) {
    const dir = project(t); const s = await server(t); const value = valid ? KEY : 'invalid-report-key';
    writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ ...(source === 'legacy' ? { key: value } : {}) }));
    if (source === 'local') writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ key: value }));
    const result = await run(dir, ['setup', '--quiet', '--no-hook'], s.api, source === 'env' ? { SAFETYVIBE_KEY: value } : {});
    assert.equal(result.code, 0); assert.equal(s.hits[0].headers['x-safetyvibe-key'], undefined);
    if (!valid) assert.match(result.stderr, /Invalid report key/);
    // With a site, a valid key is sent; an invalid key never is.
    writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ site: SITE, ...(source === 'legacy' ? { key: value } : {}) }));
    writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify(source === 'local' ? { key: value } : {}));
    const next = await run(dir, ['scan', '--quiet', '--claim-token', 'valid-claim-token'], s.api, source === 'env' ? { SAFETYVIBE_KEY: value } : {});
    assert.equal(next.code, 0); assert.equal(s.hits[1].headers['x-safetyvibe-key'], valid ? KEY : undefined);
  }
});

test('invalid response keys are not saved and malformed tokens never sent', async t => {
  const dir = project(t); const s = await server(t, () => ({ site: SITE, key: 'invalid-response-key' }));
  const result = await run(dir, ['setup', '--quiet', '--no-hook', '--claim-token', 'bad!token'], s.api);
  assert.equal(s.hits[0].headers['x-safetyvibe-claim-token'], undefined);
  assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
  assert.match(result.stderr, /Invalid claim token/); assert.match(result.stderr, /Invalid report key in server response/);
});

test('local token wins, migration precedes rejection and read-only commands never write', async t => {
  const dir = project(t); const s = await server(t, (req, res) => {
    const rc = JSON.parse(readFileSync(join(dir, '.safetyviberc.json')));
    const local = JSON.parse(readFileSync(join(dir, '.safetyviberc.local.json')));
    assert.equal(rc.key, undefined); assert.equal(rc.claimToken, undefined); assert.equal(rc.api, undefined); assert.equal(rc.url, 'https://example.com');
    assert.equal(local.key, KEY); assert.equal(local.claimToken, 'local-claim-token');
    assert.match(readFileSync(join(dir, '.gitignore'), 'utf8'), /.safetyviberc.local.json/);
    res.statusCode = 503; return { error: 'Try later' };
  });
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ key: KEY, claimToken: 'legacy-claim-token', api: 'unused', url: 'https://example.com#fragment' }));
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ claimToken: 'local-claim-token' }));
  const before = snapshot(dir);
  for (const args of [['status'], ['help'], ['setup', '--dry-run', '--json']]) { await run(dir, args, s.api); assert.deepEqual(snapshot(dir), before); }
  const result = await run(dir, ['scan', '--quiet'], s.api);
  assert.equal(result.code, 0); assert.equal(s.hits[0].headers['x-safetyvibe-claim-token'], 'local-claim-token');
  assert.match(result.stderr, /Try later/);
});

test('unwritable migration prevents sending and credential-safety errors stop persistence', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ key: KEY }));
  mkdirSync(join(dir, '.safetyviberc.local.json'));
  const result = await run(dir, ['scan', '--quiet'], s.api);
  assert.equal(result.code, 0); assert.equal(s.hits.length, 0); assert.match(result.stderr, /config is not writable.*nothing sent/);
  const other = project(t); mkdirSync(join(other, '.gitignore'));
  const saved = await run(other, ['setup', '--quiet', '--no-hook'], s.api);
  assert.equal(saved.code, 1); assert.equal(readdirSync(other).includes('.safetyviberc.local.json'), false);
  assert.match(saved.stderr, /could not verify credential-file safety; no credentials saved/i);
});

test('safety messages survive quiet and dry-run; rejection is sanitised and bounded', async t => {
  const dir = project(t); writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_ANON_KEY=sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1');
  const s = await server(t, (req, res) => { res.statusCode = 400; return { error: '\x1b\x00denied' + 'x'.repeat(400), warning: 'server warning\x1b' }; });
  for (const dry of [true, false]) {
    const result = await run(dir, ['setup', '--quiet', '--url', 'https://example.com/a%3Fb#frag', ...(dry ? ['--dry-run', '--json'] : [])], s.api);
    assert.match(result.stderr, /VITE_SUPABASE_ANON_KEY holds a Supabase secret\/service_role key/); assert.match(result.stderr, /Removed credentials\/query\/fragment or unsafe path from URL/);
    assert.doesNotMatch(result.stdout + result.stderr, /sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1|\x1b|\x00/);
    if (!dry) { assert.match(result.stderr, /server warning/); assert.match(result.stderr, /report rejected: /); assert.ok(result.stderr.split('\n').every(line => line.length < 360)); }
  }
});

for (const claimUrl of ['https://evil.example/claim', 'https://user:pass@dashboard.safetyvibe.eu/claim', 'https://dashboard.safetyvibe.eu/\x1bclaim', 123, 'http://127.0.0.1/claim']) test('untrusted claim URL uses dashboard fallback ' + typeof claimUrl, async t => {
  const dir = project(t); const s = await server(t, () => ({ site: SITE, key: KEY, claimUrl }));
  const result = await run(dir, ['setup', '--no-hook'], s.api);
  assert.match(result.stdout, /open your SafetyVibe dashboard/); assert.equal(result.stdout.split('\n').filter(l => /dashboard/i.test(l)).length, 1); assert.doesNotMatch(result.stdout, /evil.example|user:pass|\x1b/);
});

test('hook preserves indentation and newline and skips non-object scripts', async t => {
  const s = await server(t);
  for (const scripts of [null, [], 'echo hello', 42]) {
    const dir = project(t); const original = JSON.stringify({ scripts }); writeFileSync(join(dir, 'package.json'), original);
    assert.equal((await run(dir, ['setup'], s.api)).code, 0); assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), original);
  }
  for (const indent of ['  ', '    ', '\t']) for (const newline of ['', '\n', '\r\n']) {
    const dir = project(t); writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'notes', scripts: {} }, null, indent) + newline);
    assert.equal((await run(dir, ['setup'], s.api)).code, 0);
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), JSON.stringify({ name: 'notes', scripts: { postinstall: 'safetyvibe-connect scan --quiet || exit 0' } }, null, indent) + newline);
  }
});

test('missing test API is confined to refused localhost', async t => {
  const result = await run(project(t), ['setup', '--no-hook']);
  assert.match(result.stderr, /could not reach 127.0.0.1:9/);
});

test('valid same-origin HTTPS claim URL is printed using a local mocked endpoint', async t => {
  const dir = project(t); const claimUrl = 'https://localhost:9/#claim=test';
  const preload = 'globalThis.fetch = async () => new Response(JSON.stringify(' + JSON.stringify({ site: SITE, key: KEY, claimUrl }) + '));';
  const result = await run(dir, ['setup', '--no-hook'], 'https://localhost:9', { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0); assert.ok(result.stdout.includes(claimUrl));
});

test('ignore precedes private file write with mode 0600; package write warning survives quiet', async t => {
  const dir = project(t); const s = await server(t);
  const preload = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { dirname, join } from 'node:path';
    const write = fs.writeFileSync;
    fs.writeFileSync = (path, data, options) => {
      if (String(path).endsWith('.safetyviberc.local.json') && (options?.mode !== 0o600 || !fs.readFileSync(join(dirname(path), '.gitignore'), 'utf8').includes('.safetyviberc.local.json'))) throw new Error('bad write order or mode');
      if (String(path).endsWith('package.json')) throw new Error('simulated unwritable package');
      return write(path, data, options);
    }; syncBuiltinESMExports();`;
  const result = await run(dir, ['setup'], s.api, { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 1); assert.match(result.stderr, /could not write package.json/); assert.match(result.stdout, /Connected:/);
  assert.equal((result.stdout + result.stderr).split('https://dashboard.safetyvibe.eu').length - 1, 1);
  assert.equal(JSON.parse(readFileSync(join(dir, '.safetyviberc.local.json'))).key, KEY);
});

for (const file of ['package.json', '.gitignore', '.safetyviberc.json']) for (const cmd of ['setup', 'scan']) test('0.3.0 accepted report retains claim link when write fails: ' + file + ' ' + cmd, async t => {
  const dir = project(t); const claimUrl = 'https://dashboard.safetyvibe.eu/connect/claim/fixture';
  const preload = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { basename } from 'node:path';
    const write = fs.writeFileSync;
    fs.writeFileSync = (path, ...args) => {
      if (basename(String(path)) === ${JSON.stringify(file)}) throw new Error('simulated unwritable file');
      return write(path, ...args);
    }; syncBuiltinESMExports();
    globalThis.fetch = async () => new Response(${JSON.stringify(JSON.stringify({ site: SITE, key: KEY, claimed: false, claimUrl }))});`;
  const result = await run(dir, [cmd], 'https://dashboard.safetyvibe.eu/connect/api/v1', {
    SAFETYVIBE_CLAIM_TOKEN: 'valid-claim-token', NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload),
  });
  assert.equal(result.code, cmd === 'setup' ? 1 : 0);
  if (file === '.gitignore') {
    assert.doesNotMatch(result.stdout, /Connected:/);
    assert.match(result.stderr, /nothing sent/);
    assert.equal((result.stdout + result.stderr).includes(claimUrl), false);
    assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
    return;
  }
  assert.equal((result.stdout.match(/Connected:/g) || []).length, 1);
  assert.equal((result.stdout + result.stderr).split(claimUrl).length - 1, 1);
  assert.match(result.stdout, /Keys sent: 0\nConnected:/);
  if (file !== 'package.json' || cmd === 'setup') assert.match(result.stderr, /could not (?:write package.json|verify credential-file safety|save .safetyviberc.json)/i);
  if (file === '.gitignore') assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
});

for (const code of ['claim_expired', 'claim_used']) test('local ' + code + ' warning survives quiet and clears token', async t => {
  const dir = project(t); const s = await server(t, (req, res) => { res.statusCode = 401; return { code, error: 'Token refused' }; });
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ claimToken: 'local-claim-token' }));
  const result = await run(dir, ['scan', '--quiet'], s.api);
  assert.equal(result.code, 0); assert.match(result.stderr, /expired or already used/); assert.match(result.stderr, /Token refused/);
  assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
});


for (const postinstall of [false, 0, null, [], {}]) test('non-string hook skipped: ' + JSON.stringify(postinstall), async t => {
  const dir = project(t); const s = await server(t);
  const original = JSON.stringify({ name: 'notes', scripts: { postinstall } }); writeFileSync(join(dir, 'package.json'), original);
  const result = await run(dir, ['setup'], s.api);
  assert.equal(result.code, 0); assert.match(result.stderr, /Add this line by hand/); assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), original);
});

for (const cmd of ['setup', 'scan']) test('ignore-file errors block credential writes and fail only setup: ' + cmd, async t => {
  const dir = project(t); const s = await server(t); mkdirSync(join(dir, '.gitignore'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'notes', devDependencies: { 'safetyvibe-connect': '^0.2.2' } }));
  const result = await run(dir, [cmd, '--no-hook'], s.api);
  assert.equal(result.code, cmd === 'setup' ? 1 : 0); assert.match(result.stderr, /no credentials saved/i);
  assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
});

test('public-only save leaves local config absent and retains the preflight ignore rule', async t => {
  const dir = project(t); const s = await server(t, () => ({ site: SITE, claimed: true }));
  const result = await run(dir, ['setup', '--no-hook'], s.api); assert.equal(result.code, 0);
  assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
  assert.equal(readFileSync(join(dir, '.gitignore'), 'utf8'), '/.safetyviberc.local.json\n');
});

test('CLI URL alert follows actual path removal', async t => {
  const s = await server(t);
  for (const path of ['/cb&token=SECRET', '/a=b', '/p%26x', '/@u', '/eyJhbGciOi.x.y', '/my-app/dashboard', '/']) {
    const result = await run(project(t), ['setup', '--no-hook', '--url=https://h' + path], s.api);
    const removed = !['/my-app/dashboard', '/'].includes(path);
    assert.equal(result.code, 0); assert.equal(result.stderr.includes('Removed'), removed);
    assert.equal(s.hits.at(-1).body.url, /eyJ/.test(path) ? undefined : 'https://h' + (removed || path === '/' ? '' : path));
  }
});

test('claim link uses canonical parsed href', async t => {
  const dir = project(t); const claimUrl = ' https://LOCALHOST:9/a/../claim link#ok ';
  const preload = 'globalThis.fetch = async () => new Response(JSON.stringify(' + JSON.stringify({ site: SITE, key: KEY, claimUrl }) + '));';
  const result = await run(dir, ['setup', '--no-hook'], 'https://localhost:9', { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assert.equal(result.code, 0); assert.ok(result.stdout.includes(new URL(claimUrl).href)); assert.equal(result.stdout.includes(claimUrl), false);
});


test('ignore failure during token migration preserves token and alerts', async t => {
  const dir = project(t); mkdirSync(join(dir, '.gitignore'));
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ claimToken: 'local-claim-token' }));
  const s = await server(t, (req, res) => { res.statusCode = 503; return { error: 'Try later' }; });
  const result = await run(dir, ['setup', '--no-hook'], s.api);
  assert.equal(result.code, 1); assert.match(result.stderr, /no credentials saved/i);
  assert.equal(readdirSync(dir).includes('.safetyviberc.local.json'), false);
  assert.equal(JSON.parse(readFileSync(join(dir, '.safetyviberc.json'))).claimToken, 'local-claim-token');
});

for (const args of [['--dry-run', '--json'], ['--dry-run', '--json', '--url', 'https://notes.example.com']]) test('0.2.2 flag-only setup dry-run ' + args.join(' '), async t => {
  const dir = project(t); const before = snapshot(dir); const s = await server(t); const r = await run(dir, args, s.api);
  assert.equal(r.code, 0); assert.ok(JSON.parse(r.stdout).packages.length); assert.equal(s.hits.length, 0); assert.deepEqual(snapshot(dir), before);
});
test('0.2.2 flag-only claim token runs setup', async t => {
  const dir = project(t); const s = await server(t); const r = await run(dir, ['--claim-token', 'valid-claim-token'], s.api);
  assert.equal(r.code, 0); assert.equal(s.hits[0].headers['x-safetyvibe-claim-token'], 'valid-claim-token');
});
for (const mode of ['stall', 'oversize', 'cap']) for (const cmd of ['setup', 'scan']) test('0.2.2 bounded response ' + mode + ' ' + cmd, { timeout: 15000 }, async t => {
  const dir = project(t); writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ claimToken: 'valid-claim-token' }));
  writeFileSync(join(dir, '.gitignore'), '/.safetyviberc.local.json\n'); const before = snapshot(dir);
  const srv = http.createServer((req, res) => { req.resume(); res.writeHead(200, { 'content-type': 'application/json' }); res.write(mode === 'oversize' ? 'x'.repeat(65537) : '{"site":'); });
  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve)); t.after(() => { srv.closeAllConnections(); srv.close(); });
  const start = Date.now(); const r = await run(dir, [cmd], 'http://127.0.0.1:' + srv.address().port, { SAFETYVIBE_TIMEOUT_MS: mode === 'cap' ? '60000' : '1500' });
  const elapsed = Date.now() - start; assert.equal(r.code, cmd === 'scan' ? 0 : 1); assert.ok(elapsed < 12000, String(elapsed)); if (mode === 'cap') assert.ok(elapsed >= 9500); assert.deepEqual(snapshot(dir), before); assert.match(r.stderr, /could not reach/);
});
test('0.2.2 scan ignores unrelated INIT_CWD and skips anonymous uninstalled projects', async t => {
  const root = project(t); const child = project(t); const s = await server(t); const before = snapshot(root);
  writeFileSync(join(child, 'package.json'), JSON.stringify({ name: 'child', scripts: { postinstall: 'safetyvibe-connect scan --quiet || exit 0' } })); const childBefore = snapshot(child);
  for (const quiet of [false, true]) { const r = await run(child, ['scan', ...(quiet ? ['--quiet'] : [])], s.api, { INIT_CWD: root }); assert.equal(r.code, 0); assert.equal(quiet ? r.stdout : '', ''); assert.equal(r.stdout, ''); }
  assert.equal(s.hits.length, 0); assert.deepEqual(snapshot(root), before); assert.deepEqual(snapshot(child), childBefore);
  const r = await run(child, ['--dry-run', '--json'], s.api, { INIT_CWD: root }); assert.equal(JSON.parse(r.stdout).name, 'child');
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'installed-root', devDependencies: { 'safetyvibe-connect': '^0.2.2' } }));
  const used = await run(child, ['--dry-run', '--json'], s.api, { INIT_CWD: root }); assert.equal(JSON.parse(used.stdout).name, 'installed-root');
});

test('0.2.2 workspace install reports child and writes only to child', async t => {
  const root = project(t); writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'monorepo', workspaces: ['packages/*'] }));
  const rootBefore = snapshot(root); const child = join(root, 'packages', 'child'); mkdirSync(child, { recursive: true });
  writeFileSync(join(child, 'package.json'), JSON.stringify({ name: 'child', dependencies: { 'safetyvibe-connect': '^0.2.2' }, scripts: { postinstall: 'safetyvibe-connect scan --quiet || exit 0' } }));
  const s = await server(t); const r = await run(child, ['scan'], s.api, { INIT_CWD: root }); assert.equal(r.code, 0); assert.equal(s.hits[0].body.name, 'child');
  for (const [file, bytes] of Object.entries(rootBefore)) assert.equal(readFileSync(join(root, file)).toString('base64'), bytes);
  assert.deepEqual(readdirSync(root).sort(), [...Object.keys(rootBefore), 'packages'].sort()); assert.ok(readdirSync(child).includes('.safetyviberc.json'));
  const home = project(t); const homeBefore = snapshot(home); const next = await run(child, ['scan'], s.api, { INIT_CWD: home }); assert.equal(next.code, 0); assert.deepEqual(snapshot(home), homeBefore);
  writeFileSync(join(home, 'package.json'), JSON.stringify({ name: 'hook-owner', scripts: { postinstall: 'safetyvibe-connect scan --quiet || exit 0' } }));
  const dry = await run(child, ['--dry-run', '--json'], s.api, { INIT_CWD: home }); assert.equal(JSON.parse(dry.stdout).name, 'hook-owner');
});

test('0.2.2 URL metadata priority: flag, environment, rc, then package name', async t => {
  const dir = project(t); writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ url: 'https://rc.example.com' })); const s = await server(t);
  const cases = [[[], {}, 'rc.example.com'], [[], { SAFETYVIBE_URL: 'https://env.example.com' }, 'env.example.com'], [['--url', 'https://flag.example.com'], { SAFETYVIBE_URL: 'https://env.example.com' }, 'flag.example.com']];
  for (const [args, env, name] of cases) { const r = await run(dir, ['--dry-run', '--json', ...args], s.api, env); assert.equal(JSON.parse(r.stdout).name, name); }
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ url: 'https://rc.example.com', name: 'RC Name' }));
  assert.equal(JSON.parse((await run(dir, ['--dry-run', '--json'], s.api)).stdout).name, 'RC Name'); assert.equal(s.hits.length, 0);
});

test('0.2.2 no readable lockfile: no packages, one plain line, bun.lockb hint; quiet suppresses it', async t => {
  const dir = project(t); rmSync(join(dir, 'package-lock.json'));
  mkdirSync(join(dir, 'node_modules', 'private-git-dep'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'private-git-dep', 'package.json'), JSON.stringify({ name: 'private-git-dep', version: '1.2.3' }));
  const line = 'No readable lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock); using safe package.json declarations, not resolved versions.';
  let r = await run(dir, ['--dry-run', '--json'], 'http://127.0.0.1:9/connect/api/v1');
  const body = JSON.parse(r.stdout);
  assert.deepEqual(body.packages, []); assert.equal(body.lockfile, 'none'); assert.doesNotMatch(r.stdout, /private-git-dep/);
  assert.ok(r.stderr.includes(line)); assert.doesNotMatch(r.stderr, /bun install/);
  writeFileSync(join(dir, 'bun.lockb'), 'binary');
  r = await run(dir, ['--dry-run', '--json'], 'http://127.0.0.1:9/connect/api/v1');
  assert.ok(r.stderr.includes(line + ' Run `bun install --save-text-lockfile` to create bun.lock.'));
  const s = await server(t);
  r = await run(dir, ['scan', '--quiet'], s.api);
  assert.equal(r.code, 0); assert.ok(!r.stderr.includes(line));
  assert.deepEqual(s.hits.at(-1)?.body?.packages ?? [], []);
});

test('0.3.0 summary comes first even with a long package list (Replit/Blink cut off long output)', async t => {
  const dir = project(t); const s = await server(t);
  const packages = Object.fromEntries(Array.from({ length: 400 }, (_, i) => ['node_modules/pkg' + i, { version: '1.0.' + i }]));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages }));
  const dry = await run(dir, ['--dry-run', '--json'], s.api);
  assert.equal(dry.code, 0); assert.equal(s.hits.length, 0);
  assertSummary(dry.stderr, 'Dry run: nothing sent', 400, 0);
  assert.equal(JSON.parse(dry.stdout).packages.length, 400);
  const real = await run(dir, ['setup', '--no-hook'], s.api);
  assert.equal(real.code, 0, real.stderr);
  assertSummary(real.stdout, 'Connected: https://dashboard.safetyvibe.eu', 400, 0);
  const unclaimed = project(t); const s2 = await server(t, () => ({ site: SITE, key: KEY, claimed: false }));
  const r2 = await run(unclaimed, ['setup', '--no-hook'], s2.api);
  assert.equal(r2.code, 0, r2.stderr); assertSummary(r2.stdout, 'Connected: open your SafetyVibe dashboard');
});
import { createHash, randomBytes } from 'node:crypto';
import { buildReport, findSupabase } from '../lib.mjs';
import { symlinkSync } from 'node:fs';

function assertSummary(output, last, count = 1, dev = 1, supabase = 'publishable key (fingerprint only)') {
  const lines = output.trimEnd().split('\n').slice(0, 5);
  assert.deepEqual(lines, ['Platform: unknown', `Lockfile: package-lock.json, 0 direct / ${count} total (0 direct dev; ${dev} confirmed dev-only)`, 'Supabase: ' + supabase, 'Keys sent: 0', last]);
  assert.ok(lines.join('\n').length < 400);
}
const fingerprint = key => createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 8);
const token = role => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ role, iss: 'supabase', ref: 'abcdefghijklmnopqrst' })).toString('base64url') + '.' + randomBytes(24).toString('base64url');
function noKeyBytes(outputs, keys) {
  for (const output of outputs) for (const key of keys) {
    assert.equal(output.includes(key), false, 'complete key escaped');
    for (let i = 0; i <= key.length - 12; i++) assert.equal(output.includes(key.slice(i, i + 12)), false, 'key fragment escaped');
  }
}
for (const exposed of [false, true]) test('0.3.0 no key bytes in stdout, stderr, export or raw HTTP body; exposed=' + exposed, async t => {
  const dir = project(t); const s = await server(t);
  const anon = token('anon'); const publishable = 'sb_publishable_' + randomBytes(40).toString('hex');
  const service = token('service_role'); const secret = 'sb_secret_' + randomBytes(40).toString('hex');
  const keys = exposed ? [anon, publishable, service, secret] : [anon];
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nVITE_SUPABASE_ANON_KEY=' + anon + (exposed ? '\nNEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=' + publishable + '\nVITE_SUPABASE_SERVICE_ROLE_KEY=' + secret + '\nPUBLIC_EXTRA=' + service : ''));
  mkdirSync(join(dir, 'src/integrations/supabase'), { recursive: true });
  writeFileSync(join(dir, 'src/integrations/supabase/client.ts'), keys.map((key, i) => 'const value' + i + ' = "' + key + '";').join('\n'));
  const expected = { project_ref: 'abcdefghijklmnopqrst', host: 'abcdefghijklmnopqrst.supabase.co', ...(exposed ? { secret_key_exposed_client_side: true } : { key_kind: 'anon', key_fingerprint: fingerprint(anon) }) };
  const one = buildReport(dir, {}, {}); const two = buildReport(dir, {}, {});
  assert.deepEqual(one, two); assert.deepEqual(one.supabase, expected);
  assert.equal(one.versions_source, 'lockfile'); assert.equal(one.source, 'connector');
  const dry = await run(dir, ['--dry-run', '--json'], s.api); const again = await run(dir, ['--dry-run', '--json'], s.api);
  assert.equal(dry.stdout, again.stdout); assert.deepEqual(JSON.parse(dry.stdout).supabase, expected);
  const out = await run(dir, ['--dry-run', '--json', '--out', 'body.json'], s.api);
  assert.equal(out.code, 0); assert.equal(out.stdout, ''); assert.equal(readFileSync(join(dir, 'body.json'), 'utf8'), dry.stdout);
  const real = await run(dir, ['setup', '--no-hook', '--out=sent.json'], s.api);
  assert.equal(real.code, 0, real.stderr); assert.equal(s.hits.length, 1);
  assert.equal(s.hits[0].raw, dry.stdout); assert.deepEqual(s.hits[0].body.supabase, expected);
  assert.equal(readFileSync(join(dir, 'sent.json'), 'utf8'), dry.stdout);
  noKeyBytes([JSON.stringify(one), dry.stdout, dry.stderr, again.stdout, again.stderr, out.stdout, out.stderr, real.stdout, real.stderr, s.hits[0].raw, readFileSync(join(dir, 'body.json'), 'utf8'), readFileSync(join(dir, 'sent.json'), 'utf8')], keys);
  if (exposed) {
    for (const name of ['PUBLIC_EXTRA', 'src/integrations/supabase/client.ts']) assert.equal(dry.stderr.split('\n').filter(line => line.startsWith('WARNING: ' + name + ' ')).length, 1);
    const quiet = await run(dir, ['scan', '--quiet'], s.api); assert.equal(quiet.stdout, ''); assert.match(quiet.stderr, /Rotate it in Supabase now/); noKeyBytes([quiet.stdout, quiet.stderr], keys);
  }
});

test('0.3.0 summary-only modes and claim link occur exactly once', async t => {
  const dir = project(t); const s = await server(t);
  const dry = await run(dir, ['--dry-run', '--json', '--summary'], s.api);
  assertSummary(dry.stdout, 'Dry run: nothing sent'); assert.equal(dry.stdout.trimEnd().split('\n').length, 6); assert.equal(dry.stderr, ''); assert.equal(s.hits.length, 0);
  const real = await run(dir, ['setup', '--summary'], s.api);
  assertSummary(real.stdout, 'Connected: https://dashboard.safetyvibe.eu'); assert.equal(real.stdout.trimEnd().split('\n').length, 6);
  const claimUrl = 'https://localhost:9/claim#test';
  const preload = 'globalThis.fetch = async () => new Response(JSON.stringify(' + JSON.stringify({ site: SITE, key: KEY, claimUrl }) + '));';
  const claimed = await run(project(t), ['setup', '--summary'], 'https://localhost:9/connect/api/v1', { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) });
  assertSummary(claimed.stdout, 'Connected: ' + claimUrl); assert.equal((claimed.stdout + claimed.stderr).split(claimUrl).length - 1, 1);
});

test('0.3.0 output refuses existing files, extensions and lexical or symlink escapes before network', async t => {
  const dir = project(t); const outside = project(t); const s = await server(t);
  writeFileSync(join(dir, 'existing.json'), 'keep');
  symlinkSync(outside, join(dir, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  for (const path of ['existing.json', 'body.txt', '../outside.json', join(outside, 'outside.json'), 'escape/body.json', 'missing/body.json', '.safetyviberc.json', '.safetyviberc.local.json']) {
    for (const args of [['--dry-run', '--json'], ['setup'], ['scan', '--quiet']]) {
      const r = await run(dir, [...args, '--out', path], s.api);
      assert.equal(r.code, 2); assert.equal(r.stdout, ''); assert.match(r.stderr, /Could not write --out/);
    }
  }
  assert.equal(readFileSync(join(dir, 'existing.json'), 'utf8'), 'keep'); assert.equal(s.hits.length, 0);
  const absolute = await run(dir, ['--dry-run', '--json', '--out=' + join(dir, 'absolute.json')], s.api); assert.equal(absolute.code, 0); assert.equal(absolute.stdout, '');
});

test('0.3.0 secret detection covers every prefix, env layer and source even with complete config', async t => {
  const dir = project(t); const anon = token('anon'); const secret = 'sb_secret_' + randomBytes(24).toString('hex');
  writeFileSync(join(dir, '.env'), '');
  const serverOnly = { SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co', SUPABASE_SERVICE_ROLE_KEY: secret };
  Object.defineProperty(serverOnly, 'SUPABASE_ANON_KEY', { enumerable: true, get() { throw new Error('server-only value read'); } });
  assert.equal(buildReport(dir, {}, serverOnly).supabase, null);
  for (const prefix of ['VITE_', 'NEXT_PUBLIC_', 'EXPO_PUBLIC_', 'PUBLIC_', 'REACT_APP_', 'NUXT_PUBLIC_']) {
    const env = { ...{ VITE_SUPABASE_URL: 'https://ABCDEFGHIJKLMNOPQRST.supabase.co', VITE_SUPABASE_ANON_KEY: anon }, [prefix + 'OTHER']: secret };
    assert.deepEqual(buildReport(dir, {}, env).supabase, { project_ref: 'abcdefghijklmnopqrst', host: 'abcdefghijklmnopqrst.supabase.co', secret_key_exposed_client_side: true });
    for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) {
      writeFileSync(join(dir, file), prefix + 'OTHER=' + secret);
      assert.deepEqual(buildReport(dir, {}, {}).supabase, { project_ref: null, host: null, secret_key_exposed_client_side: true });
      // Overriding the variable does not hide an exposure in another config layer.
      assert.ok(findSupabase(dir, { [prefix + 'OTHER']: 'safe' }).warnings.includes(prefix + 'OTHER'));
      rmSync(join(dir, file));
    }
  }
  mkdirSync(join(dir, 'src/lib'), { recursive: true });
  writeFileSync(join(dir, 'src/lib/supabase.ts'), '"use server"; const secret = "' + secret + '";');
  assert.equal(buildReport(dir, {}, {}).supabase, null);
  writeFileSync(join(dir, 'src/lib/supabase.ts'), 'const anyName = "' + secret + '";');
  assert.equal(buildReport(dir, {}, { VITE_SUPABASE_URL: 'https://abc.supabase.co', VITE_SUPABASE_ANON_KEY: anon }).supabase.secret_key_exposed_client_side, true);
  const r = await run(dir, ['setup', '--quiet'], 'http://127.0.0.1:9/connect/api/v1');
  assert.match(r.stderr.split('\n')[0], /^WARNING: src\/lib\/supabase.ts/); assert.match(r.stderr.trimEnd().split('\n').at(-1), /could not reach/);
});

for (const marker of ['sb_publishable_abcdefghijklmnop123456789', 'sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 'eyJabc.def.ghi', 'sk_live_fixture', 'sk_test_fixture', 'sk-ant-api03-fixture', 'sk-proj-fixture', 'rk_live_fixture', 'service_role', 'svk_fixture', 'a1'.repeat(30), 'sb%255Fsecret%255Ffixture', 'sb_\u200esecret_fixture', 'еyJabc.def.ghi']) test('shared screening drops ' + marker.slice(0, 12), async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: {
    // A long alnum run is a valid npm name and exempt from the long-run rule; key prefixes are not.
    ['node_modules/' + (marker === 'a1'.repeat(30) ? 'sk-ant-api03-fixture' : marker)]: { version: '1.0.0' },
    'node_modules/safe-version': { version: '1.0.0-' + marker },
    'node_modules/safe': { version: '1.0.0' }
  } }));
  for (const mode of [['--dry-run', '--json'], ['setup', '--no-hook']]) {
    const result = await run(dir, [...mode, '--name', 'prefix ' + marker, '--url', 'https://example.com/' + marker], s.api, { SAFETYVIBE_ENV: marker });
    assert.equal(result.code, mode[0] === '--dry-run' ? 0 : 1);
    if (mode[0] === '--dry-run') assert.equal(JSON.parse(result.stdout).incomplete, true);
    else assert.match(result.stderr, /incomplete.*nothing sent/i);
    let stdout = result.stdout;
    const longSemver = marker === 'a1'.repeat(30);
    if (longSemver && mode[0] === '--dry-run') {
      const report = JSON.parse(stdout);
      assert.deepEqual(report.packages.find(p => p.name === 'safe-version'), { ecosystem: 'npm', name: 'safe-version', version: '1.0.0-' + marker });
      stdout = JSON.stringify({ ...report, packages: report.packages.filter(p => p.name !== 'safe-version') });
    }
    assert.ok(!(stdout + result.stderr + JSON.stringify(s.hits.map(h => h.body))).includes(marker));
    for (const field of ['name', 'url', 'environment', 'package name', ...(!longSemver ? ['package version'] : [])]) assert.ok(result.stderr.includes('Dropped ' + field + ': it looked like a key.'), field);
  }
  assert.equal(s.hits.length, 0);
});

test('screening names the exposed variable, keeps ordinary names, warns once after the summary', async t => {
  const dir = project(t); const s = await server(t);
  const service = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from('{"role":"service_role"}').toString('base64url') + '.sig';
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nVITE_SUPABASE_SERVICE_ROLE_KEY=' + service);
  const longName = '@opentelemetry/instrumentation-aws-lambda-extension-wrapper';
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: {
    'node_modules/honeyjar': { version: '1.0.0' }, 'node_modules/journeyjs': { version: '2.0.0' }, ['node_modules/' + longName]: { version: '1.0.0' },
    'node_modules/sk-ant-api03-fixture': { version: '1.0.0' } } }));
  const result = await run(dir, ['--dry-run', '--json', '--name', 'My honeyjar app', '--url', 'https://notes.example.com/some-long-path/another-segment/settings-page'], s.api);
  assert.equal(result.code, 0);
  const body = JSON.parse(result.stdout);
  assert.deepEqual(body.packages.map(p => p.name).sort(), [longName, 'honeyjar', 'journeyjs'].sort());
  assert.equal(body.name, 'My honeyjar app'); assert.equal(body.url, 'https://notes.example.com/some-long-path/another-segment/settings-page');
  const lines = result.stderr.trimEnd().split('\n');
  assert.equal(lines[0], 'Platform: unknown'); assert.equal(lines[4], 'Dry run: nothing sent');
  assert.ok(lines.includes('WARNING: VITE_SUPABASE_SERVICE_ROLE_KEY holds a Supabase secret/service_role key in client-exposed config; every visitor can read it. Rotate it in Supabase now. Only a flag is sent, never the key.'));
  assert.equal(lines.filter(l => l === 'Dropped package name: it looked like a key.').length, 1);
  assert.ok(lines.indexOf('Dropped package name: it looked like a key.') > 4);
  assert.ok(!(result.stdout + result.stderr).includes('sk-ant-api03'));
});

test('a key-like server message is not echoed', async t => {
  const dir = project(t); const s = await server(t, (req, res) => { res.statusCode = 400; return { error: 'bad sb_secret_' + 'q7'.repeat(20) }; });
  const result = await run(dir, ['setup', '--no-hook'], s.api);
  assert.equal(result.code, 1); assert.match(result.stderr, /report rejected: \[text removed: it looked like a key\]/); assert.doesNotMatch(result.stderr, /q7q7q7/);
});

test('exposed-secret dry-run explanation and --out remain offline', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, '.env'), 'VITE_SUPABASE_ANON_KEY=sb_secret_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1');
  const result = await run(dir, ['--dry-run', '--json', '--out', 'report.json'], s.api);
  assert.equal(result.code, 0); assert.equal(result.stdout, ''); assert.equal(s.hits.length, 0);
  assert.match(result.stderr, /A secret key is exposed in client code; only that fact is reported, never the key\./);
  assert.doesNotMatch(result.stderr, /The anon key is public by design/);
  assert.equal(JSON.parse(readFileSync(join(dir, 'report.json'))).supabase.secret_key_exposed_client_side, true);
  assert.match((await run(dir, ['--help'], s.api)).stdout, /--out FILE.json writes the body without sending/);
});


test('0.3.1 Lovable prefix checks keep the public fingerprint; real secrets still warn', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, '.env'), '');
  mkdirSync(join(dir, 'src/integrations/supabase'), { recursive: true });
  const file = join(dir, 'src/integrations/supabase/client.ts');
  const publishable = 'sb_publishable_' + 'p7'.repeat(16);
  const base = `const SUPABASE_URL = "https://lovablefixtureref000.supabase.co"; const SUPABASE_PUBLISHABLE_KEY = "${publishable}"; createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);`;
  const checks = [
    'if (SUPABASE_PUBLISHABLE_KEY.startsWith("sb_secret_")) throw new Error("unexpected key");',
    'xh=e=>e.startsWith(`sb_publishable_`)||e.startsWith(`sb_secret_`)\nfunction Bh(e){return e.startsWith(`sb_publishable_`)||e.startsWith(`sb_secret_`)}',
    '"sb_secret_" === k; k !== \'sb_secret_\'; k.includes(\'sb_secret_\'); k.indexOf("sb_secret_"); const short = \'sb_secret_abc\';',
    'const incomplete = "' + token('service_role').split('.').slice(0, 2).join('.') + '";',
  ];
  for (const [i, check] of checks.entries()) {
    writeFileSync(file, base + check);
    const r = await run(dir, ['setup', '--dry-run', '--json'], s.api);
    assert.equal(r.code, 0); assert.match(r.stderr, /publishable key \(fingerprint only\)/); assert.doesNotMatch(r.stderr, /WARNING/);
    const body = JSON.parse(r.stdout);
    assert.equal(body.supabase.key_kind, 'publishable'); assert.equal(body.supabase.key_fingerprint, fingerprint(publishable));
    assert.equal(body.supabase.secret_key_exposed_client_side, undefined, 'fp-lovable-fixture ' + i);
    noKeyBytes([r.stdout, r.stderr], [publishable]);
  }
  for (const secret of ['sb_secret_' + 'q9'.repeat(20), token('service_role')]) {
    writeFileSync(file, base + 'const k = "' + secret + '";');
    const r = await run(dir, ['setup', '--dry-run', '--json'], s.api);
    assert.equal(r.code, 0); assert.match(r.stderr, /WARNING:.*Rotate it/);
    assert.equal(JSON.parse(r.stdout).supabase.secret_key_exposed_client_side, true);
    assert.equal(JSON.parse(r.stdout).supabase.key_fingerprint, undefined);
    noKeyBytes([r.stdout, r.stderr], [secret, publishable]);
  }
  assert.equal(s.hits.length, 0);
});

test('0.3.1 Emergent non-TTY default stays within six lines for 1486 packages', async t => {
  const dir = project(t); const s = await server(t);
  rmSync(join(dir, 'package-lock.json')); writeFileSync(join(dir, '.env'), ''); mkdirSync(join(dir, '.emergent'));
  writeFileSync(join(dir, 'yarn.lock'), '# yarn lockfile v1\n' + Array.from({ length: 1486 }, (_, i) => `fixture-${i}@^1.0.0:\n  version "1.0.0"\n`).join('\n'));
  const before = readdirSync(dir).sort();
  const r = await run(dir, ['setup', '--dry-run'], s.api);
  assert.equal(r.code, 0); assert.equal(r.stderr, '');
  const lines = r.stdout.trim().split('\n');
  assert.deepEqual(lines.slice(0, 5), ['Platform: Emergent', 'Lockfile: yarn.lock, 0 direct / 1486 total (0 direct dev; 0 confirmed dev-only)', 'Supabase: none', 'Keys sent: 0', 'Dry run: nothing sent']);
  assert.match(lines[5], /^Next: .*inventory --json --compact; verify receiver support before pasting\.$/);
  assert.ok((r.stdout + r.stderr).trim().split('\n').length <= 6); assert.equal(s.hits.length, 0); assert.deepEqual(readdirSync(dir).sort(), before);
  const full = await run(dir, ['setup', '--dry-run', '--json'], s.api); assert.equal(JSON.parse(full.stdout).packages.length, 1486);
  const both = await run(dir, ['setup', '--dry-run', '--json', '--summary'], s.api); assert.equal(both.stdout, r.stdout); assert.equal(both.stderr, '');
});

test('0.3.1 TTY output stays JSON unless automation or CI is detected', async t => {
  const dir = project(t); const s = await server(t);
  const preload = "Object.defineProperty(process.stdout, 'isTTY', { value: true });";
  const clean = Object.fromEntries(Object.keys(process.env)
    .filter(k => !/^(PATH|SYSTEMROOT|WINDIR|TEMP|TMP|TMPDIR|COMSPEC|PATHEXT)$/i.test(k))
    .map(k => [k, undefined]));
  const extra = { ...clean, NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) };
  const tty = await run(dir, ['--dry-run'], s.api, extra); assert.equal(JSON.parse(tty.stdout).v, 1); assertSummary(tty.stderr, 'Dry run: nothing sent');
  for (const env of ['CI', 'REPLIT', 'REPL_ID', 'LOVABLE', 'BOLT', 'EMERGENT', 'BASE44_AGENT', 'TERM']) {
    const r = await run(dir, ['--dry-run'], s.api, { ...extra, [env]: env === 'TERM' ? 'dumb' : '1' });
    assertSummary(r.stdout.replace('Platform: Replit', 'Platform: unknown'), 'Dry run: nothing sent'); assert.equal(r.stdout.trim().split('\n').length, 6); assert.equal(r.stderr, '');
  }
  assert.equal(s.hits.length, 0);
});

test('0.3.1 linked project does not re-send the env claim token', async t => {
  const dir = project(t); const s = await server(t); const env = { SAFETYVIBE_CLAIM_TOKEN: 'valid-claim-token' };
  assert.equal((await run(dir, ['setup', '--no-hook'], s.api, env)).code, 0);
  assert.equal(s.hits[0].headers['x-safetyvibe-claim-token'], env.SAFETYVIBE_CLAIM_TOKEN);
  assert.equal((await run(dir, ['setup', '--no-hook'], s.api, env)).code, 0);
  assert.equal(s.hits.length, 2); assert.equal(s.hits[1].headers['x-safetyvibe-claim-token'], undefined);
  assert.equal(s.hits[1].headers['x-safetyvibe-key'], KEY);
});

for (const file of ['.safetyviberc.json', '.safetyviberc.local.json', 'directory']) test('0.3.1 unwritable config sends zero requests: ' + file, async t => {
  const dir = project(t); const s = await server(t);
  // A directory at either file path is a realistic Windows write failure. The preload models a read-only project directory.
  if (file !== 'directory') mkdirSync(join(dir, file));
  const preload = `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
    const write = fs.writeFileSync; fs.writeFileSync = (path, ...args) => { if (String(path).includes('.safetyvibe-write-')) throw new Error('read-only directory'); return write(path, ...args); }; syncBuiltinESMExports();`;
  const extra = { SAFETYVIBE_CLAIM_TOKEN: 'valid-claim-token', ...(file === 'directory' ? { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(preload) } : {}) };
  for (const cmd of ['setup', 'scan']) {
    const r = await run(dir, [cmd], s.api, extra);
    assert.equal(r.code, cmd === 'setup' ? 1 : 0); assert.match(r.stderr, /config is not writable.*nothing sent/); assert.doesNotMatch(r.stdout, /Connected:/);
  }
  assert.equal(s.hits.length, 0); assert.ok(!readdirSync(dir).some(f => f.startsWith('.safetyvibe-write-')));
});

test('0.3.1 service-role variable names warn locally; client exposure has its own warning', async t => {
  const dir = project(t); const s = await server(t); const secret = 'sb_secret_' + 'q9'.repeat(20);
  const names = ['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SERVICE_KEY', 'CUSTOM_SERVICE_ROLE_TOKEN'];
  for (const layer of ['process', '.env', '.env.local', '.env.production', '.env.production.local']) {
    for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) writeFileSync(join(dir, file), '');
    const values = Object.fromEntries(names.map(name => [name, secret]));
    if (layer !== 'process') writeFileSync(join(dir, layer), names.map(name => name + '=' + secret).join('\n'));
    const r = await run(dir, ['--dry-run', '--json'], s.api, layer === 'process' ? values : {});
    assert.equal(r.code, 0); assert.equal(JSON.parse(r.stdout).supabase, null);
    // Server-side process env is normal: only .env* files get the reminder.
    for (const name of names) assert.equal(r.stderr.includes(`found a service-role key variable (${name}); make sure it is never in client code`), layer !== 'process', layer + ' ' + name);
    assert.doesNotMatch(r.stderr, /WARNING:|Rotate it/); noKeyBytes([r.stdout, r.stderr], [secret]);
  }
  for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) writeFileSync(join(dir, file), '');
  const r = await run(dir, ['--dry-run', '--json'], s.api, { VITE_SUPABASE_SERVICE_ROLE_KEY: secret });
  assert.doesNotMatch(r.stderr, /found a service-role key variable/); assert.match(r.stderr, /WARNING: VITE_SUPABASE_SERVICE_ROLE_KEY.*Rotate it/);
  assert.equal(JSON.parse(r.stdout).supabase.secret_key_exposed_client_side, true); noKeyBytes([r.stdout, r.stderr], [secret]); assert.equal(s.hits.length, 0);
});


test('0.3.1 missing --out is a usage error even for scan', async t => {
  const dir = project(t); const s = await server(t);
  for (const args of [['scan', '--out'], ['scan', '--out='], ['scan', '--out', '--summary']]) {
    const r = await run(dir, args, s.api); assert.equal(r.code, 2); assert.match(r.stderr, /Missing value for --out/);
  }
  assert.equal(s.hits.length, 0);
});

test('0.3.1 status remains visible on non-TTY output', async t => {
  const dir = project(t); const s = await server(t);
  const before = snapshot(dir); const first = await run(dir, ['status'], s.api);
  assert.equal(first.code, 0); assert.equal(first.stdout, 'Not linked.\n'); assert.deepEqual(snapshot(dir), before);
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ site: SITE }));
  const linked = await run(dir, ['status'], s.api); assert.equal(linked.code, 0); assert.match(linked.stdout, /Linked to SafetyVibe app/);
  const missing = await run(dir, ['scan', '--quiet'], s.api); assert.equal(missing.code, 0); assert.equal(missing.stdout, ''); assert.match(missing.stderr, /report key is not on this machine/); assert.equal(s.hits.length, 0);
});

test('0.3.1 an apostrophe in a comment cannot hide a real quoted secret', async t => {
  const dir = project(t); const s = await server(t); const secret = 'sb_secret_' + 'Zx8'.repeat(14);
  mkdirSync(join(dir, 'src', 'lib'), { recursive: true });
  writeFileSync(join(dir, 'src', 'lib', 'supabase.ts'), "// we're using the admin key here\nconst SUPABASE_KEY = \"" + secret + "\";\nexport const opts = { storage: 'local' };\n");
  const r = await run(dir, ['--dry-run', '--json'], s.api);
  assert.equal(JSON.parse(r.stdout).supabase.secret_key_exposed_client_side, true);
  assert.match(r.stderr, /WARNING: src\/lib\/supabase\.ts holds a Supabase secret/); noKeyBytes([r.stdout, r.stderr], [secret]);
  writeFileSync(join(dir, 'src', 'lib', 'supabase.ts'), "// we're checking\nif (k === \"" + secret + "\") throw 1;\nconst o = { a: 'b' };\n");
  const compared = await run(dir, ['--dry-run', '--json'], s.api);
  assert.match(compared.stderr, /WARNING:/);
  assert.equal(JSON.parse(compared.stdout).supabase.secret_key_exposed_client_side, true);
  noKeyBytes([compared.stdout, compared.stderr], [secret]);
  assert.equal(s.hits.length, 0);
});

test('root hints and explicit frontend selection preserve a linked root', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: {} }));
  writeFileSync(join(dir, '.safetyviberc.json'), JSON.stringify({ site: SITE, url: 'https://root.example' }));
  writeFileSync(join(dir, '.safetyviberc.local.json'), JSON.stringify({ key: KEY }));
  const child = join(dir, 'frontend'); mkdirSync(child);
  writeFileSync(join(child, 'package.json'), JSON.stringify({ dependencies: { app: '^1' }, devDependencies: { tool: '^2' } }));
  writeFileSync(join(child, 'yarn.lock'), '# yarn lockfile v1\napp@^1:\n  version "1.0.0"\n\ntool@^2:\n  version "2.0.0"\n');
  const rc = readFileSync(join(dir, '.safetyviberc.json'), 'utf8');
  const root = await run(dir, ['inventory', '--json', '--compact'], s.api);
  assert.deepEqual(JSON.parse(root.stdout).packages, []);
  assert.match(root.stderr, /\.\/frontend.*--project DIR/);
  const selected = await run(dir, ['inventory', '--project=frontend', '--json', '--compact'], s.api);
  const body = JSON.parse(selected.stdout);
  assert.equal(body.lockfile, 'yarn.lock'); assert.equal(body.packages.length, 2);
  assert.match(selected.stderr, /2 direct \/ 2 total \(1 direct dev; 1 confirmed dev-only\)/);
  assert.equal(readFileSync(join(dir, '.safetyviberc.json'), 'utf8'), rc);
  assert.equal(s.hits.length, 0);
  for (const hint of ['..', 'missing', dir]) {
    const invalid = await run(dir, ['setup', '--project', hint], s.api);
    assert.equal(invalid.code, 2); assert.match(invalid.stderr, /Invalid --project/);
  }
  assert.equal(s.hits.length, 0);
});

test('compact inventory retains 1485 packages in <=200 lines, is offline and writes only --out', async t => {
  const dir = project(t); const s = await server(t);
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: Object.fromEntries(Array.from({ length: 1485 }, (_, i) => ['node_modules/package-' + i, { version: '1.0.0' }])) }));
  const before = snapshot(dir);
  const trap = "globalThis.fetch = () => { throw new Error('offline route called fetch'); };";
  const extra = { NODE_OPTIONS: '--import=data:text/javascript,' + encodeURIComponent(trap) };
  const r = await run(dir, ['inventory', '--json', '--compact'], s.api, extra);
  assert.equal(r.code, 0, r.stderr); assert.ok(r.stdout.split('\n').length <= 200);
  assert.equal(JSON.parse(r.stdout).packages.length, 1485); assert.deepEqual(snapshot(dir), before);
  const exported = await run(dir, ['inventory', '--json', '--compact', '--out', 'inventory.json'], s.api, extra);
  assert.equal(exported.code, 0); assert.equal(exported.stdout, '');
  assert.equal(readFileSync(join(dir, 'inventory.json'), 'utf8'), r.stdout);
  const rejected = await run(dir, ['inventory', '--out', 'inventory.json'], s.api);
  assert.equal(rejected.code, 2); assert.equal(s.hits.length, 0);
  assert.equal((await run(dir, ['scan', '--compact', '--out=../escape.json'], s.api)).code, 2);
});

test('explicit summary precedence is independent of order; compact alone does not opt into JSON', async t => {
  const dir = project(t); const s = await server(t);
  for (const flags of [['--json', '--compact', '--summary'], ['--summary', '--compact', '--json'], ['--json=summary', '--json', '--compact'], ['--json', '--json=summary'], ['--compact']]) {
    const r = await run(dir, ['inventory', ...flags], s.api);
    assert.equal(r.code, 0); assertSummary(r.stdout, 'Dry run: nothing sent');
    assert.equal(r.stdout.trim().split('\n').length, 6); assert.equal(r.stderr, '');
  }
  const exported = await run(dir, ['inventory', '--json', '--json=summary', '--compact', '--out=summary.json'], s.api);
  assertSummary(exported.stdout, 'Dry run: nothing sent'); assert.equal(JSON.parse(readFileSync(join(dir, 'summary.json'))).v, 1);
  assert.equal((await run(dir, ['inventory', '--json=wrong'], s.api)).code, 2);
  for (const flag of ['--project', '--compact', '--json=summary']) assert.equal((await run(dir, ['inventory', '--url', flag], s.api)).code, 2);
  assert.equal(s.hits.length, 0);
});

test('declared ranges stay exact and real reports remain offline', async t => {
  const dir = project(t); const s = await server(t); rmSync(join(dir, 'package-lock.json'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { react: '^18.2.0' }, devDependencies: { vite: '~6.0.0' } }));
  const before = snapshot(dir);
  const local = await run(dir, ['inventory', '--json', '--compact'], s.api);
  const body = JSON.parse(local.stdout);
  assert.equal(body.versions_source, 'declared'); assert.equal(body.lockfile, 'none');
  assert.deepEqual(body.packages.map(p => p.version), ['~6.0.0', '^18.2.0']);
  assert.match(local.stderr, /2 direct \/ 2 declared/); assert.equal(local.code, 0);
  const blocked = await run(dir, ['setup', '--no-hook'], s.api);
  assert.equal(blocked.code, 1); assert.match(blocked.stderr, /receiver support is not verified; nothing sent/);
  assert.equal(s.hits.length, 0); assert.deepEqual(snapshot(dir), before);
});

test('real JSON stays machine-readable and summary includes one hook/manual guidance line', async t => {
  const dir = project(t); const s = await server(t);
  const r = await run(dir, ['setup', '--json', '--compact', '--no-hook'], s.api);
  assert.equal(r.code, 0, r.stderr); assert.deepEqual(JSON.parse(r.stdout), s.hits[0].body);
  assert.equal(r.stdout.trim().split('\n').length, 1); assert.match(r.stderr, /Connected:/);
  assert.equal(r.stderr.split('\n').filter(l => l.startsWith('Next:')).length, 1);
  const summary = await run(dir, ['setup', '--summary', '--no-hook'], s.api);
  assert.equal(summary.stdout.split('\n').filter(l => l.startsWith('Next:')).length, 1);
  assert.match(summary.stdout, /Re-report manually:/);
  const hooked = await run(project(t), ['setup', '--summary'], s.api);
  assert.match(hooked.stdout, /Next: SafetyVibe: postinstall hook added/);
  const unsafe = project(t);
  writeFileSync(join(unsafe, 'package.json'), JSON.stringify({ scripts: { postinstall: 'echo "$SECRET"' } }));
  const skipped = await run(unsafe, ['setup', '--summary'], s.api);
  assert.match(skipped.stdout, /Next: SafetyVibe: postinstall hook skipped/);
  assert.equal(skipped.stdout.split('\n').filter(l => l.startsWith('Next:')).length, 1);
  assert.match(skipped.stderr, /Could not safely chain postinstall/);
});

test('compact inventory JSON and export never leak embedded or compared secret bytes', async t => {
  const dir = project(t); const s = await server(t); const secret = 'sb_secret_' + randomBytes(28).toString('hex');
  mkdirSync(join(dir, 'src/lib'), { recursive: true });
  writeFileSync(join(dir, 'src/lib/supabase.ts'), `k === "${secret}";`);
  writeFileSync(join(dir, '.env'), `VITE_EXTRA="PUB # old ${secret}"\n`);
  const local = await run(dir, ['inventory', '--json', '--compact'], s.api);
  assert.equal(JSON.parse(local.stdout).supabase.secret_key_exposed_client_side, true);
  assert.match(local.stderr, /WARNING:/); noKeyBytes([local.stdout, local.stderr], [secret]);
  const exported = await run(dir, ['inventory', '--json', '--compact', '--out=compact.json'], s.api);
  assert.equal(exported.stdout, '');
  const text = readFileSync(join(dir, 'compact.json'), 'utf8');
  assert.equal(JSON.parse(text).supabase.secret_key_exposed_client_side, true);
  noKeyBytes([text, exported.stderr], [secret]); assert.equal(s.hits.length, 0);
});
