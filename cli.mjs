#!/usr/bin/env node
import { readFileSync, writeFileSync, chmodSync, unlinkSync, realpathSync, accessSync, statSync, constants } from 'node:fs';
import { join, resolve, relative, dirname, isAbsolute, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildReport, findSupabase, normPublicUrl, urlNeedsCleaning, withHook, HOOK, packageManager, readPackages, screenString, secretLike, takeScreenWarnings, inventoryCounts, discoverProjects, selectProject, projectPath, readProjectFile } from './lib.mjs';
const GIT_TIMEOUT_MS = 15000;
const RC = '.safetyviberc.json';
const LOCAL = '.safetyviberc.local.json';
const DEFAULT_API = 'https://dashboard.safetyvibe.eu/connect/api/v1';
const REPORT_KEY = /^svk_[A-Za-z0-9_-]{32}$/;
const CLAIM_TOKEN = /^[A-Za-z0-9_-]{16,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USAGE = 'Usage: safetyvibe-connect setup|scan|inventory|status|help [--claim-token TOKEN] [--url URL] [--name NAME] [--project DIR] [--dry-run] [--summary|--json=summary] [--json] [--compact] [--out FILE.json] [--quiet] [--no-hook] [--help/-h] [--version/-v]\n--dry-run and inventory: no network; non-TTY/automation default is summary. --json: full body on stdout, summary on stderr. --compact: one-line JSON. Precedence: --summary/--json=summary > --out > --json; --out still exports the body. --dry-run --out FILE.json writes the body without sending. inventory --json --compact is the local inventory route; paste receiver compatibility requires separate verification.';
const argv = process.argv.slice(2);
const flags = {};
let cmd = ''; let error = '';
// Complete argument validation before reading even package.json.
for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (!arg.startsWith('-')) {
    if (cmd || !['setup', 'scan', 'inventory', 'status', 'help'].includes(arg)) { error = 'Unknown command or argument.'; break; }
    cmd = arg; continue;
  }
  const [raw, ...rest] = arg.split('=');
  const name = ({ '-h': 'help', '-v': 'version' })[raw] || raw.replace(/^--/, '');
  if (['claim-token', 'url', 'name', 'out', 'project'].includes(name)) {
    const value = rest.length ? rest.join('=') : argv[++i];
    if (!value || (!rest.length && /^(?:--(?:dry-run|quiet|no-hook|help|version|claim-token|url|name|summary|json|compact|out|project)|-h|-v)(?:=|$)/.test(value))) { error = 'Missing value for --' + name + '.'; break; }
    flags[name] = value;
  } else if (name === 'json' && rest.join('=') === 'summary') flags.summary = true;
  else if (['dry-run', 'quiet', 'no-hook', 'help', 'version', 'summary', 'json', 'compact'].includes(name) && !rest.length) flags[name] = true;
  else { error = 'Unknown flag.'; break; }
}
if (error) {
  const scan = cmd === 'scan' || argv[0] === 'scan';
  if (!(scan && argv.includes('--quiet'))) console.error(USAGE + '\n' + error);
  process.exit(scan && !error.startsWith('Missing value for --out') ? 0 : 2);
}
if (!argv.length || cmd === 'help' || flags.help) { console.log(USAGE); process.exit(0); }
if (!cmd) cmd = 'setup';
if (cmd === 'inventory') flags['dry-run'] = true;
const VERSION = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;
if (flags.version) { console.log(VERSION); process.exit(0); }
function installed(dir, hook = false) {
  try { const p = JSON.parse(readProjectFile(dir, 'package.json')); return ['dependencies', 'devDependencies', 'optionalDependencies'].some(k => Object.hasOwn(p[k] || {}, 'safetyvibe-connect')) || (hook && /(?:^|[\s(])safetyvibe-connect\s+scan\b/.test(p.scripts?.postinstall || '')); } catch { return false; }
}
function workspaceRoot(dir) {
  try { const p = JSON.parse(readProjectFile(dir, 'package.json')); if (p.workspaces) return true; } catch {}
  // pnpm 10 also writes pnpm-workspace.yaml for build settings in single apps: only a packages list counts.
  try { return /^packages\s*:/m.test(readProjectFile(dir, 'pnpm-workspace.yaml')); } catch { return false; }
}
let root = process.env.INIT_CWD && process.env.INIT_CWD !== process.cwd() && !workspaceRoot(process.env.INIT_CWD) && installed(process.env.INIT_CWD, true) ? process.env.INIT_CWD : process.cwd();
try { root = selectProject(root, flags.project); } catch { console.error('Invalid --project: choose an existing project directory inside the current project root.'); process.exit(cmd === 'scan' ? 0 : 2); }
const summaryOnly = flags.summary || (!flags.json && !flags.out && (!process.stdout.isTTY || process.env.TERM === 'dumb' || (process.env.CI && !/^(false|0)$/i.test(process.env.CI)) || Object.keys(process.env).some(k => /^(REPLIT.*|REPL_ID|LOVABLE.*|BOLT.*|EMERGENT.*|BASE44_.*|GITHUB_ACTIONS|GITLAB_CI|BUILD_ID|CONTINUOUS_INTEGRATION)$/.test(k))));
const machineJson = flags.json && !summaryOnly && !flags.out;
const say = (...args) => { if (!flags.quiet && !flags['dry-run'] && !flags.summary && (cmd === 'status' || !summaryOnly)) (machineJson ? console.error : console.log)(...args); };
const warnings = [];
const alert = message => warnings.push(message);
const flushWarnings = () => { for (const message of [...takeScreenWarnings(), ...warnings.splice(0)]) console.error(message); };
const safeText = value => { const text = String(value).replace(/[\x00-\x1f\x7f-\x9f]/g, ''); return (secretLike(text, false, false) ? '[text removed: it looked like a key]' : text).slice(0, 300); };
// Variable names such as VITE_SUPABASE_SERVICE_ROLE_KEY are printed; only names that carry key material are hidden.
const safeName = value => { const text = String(value).replace(/[\x00-\x1f\x7f-\x9f]/g, ''); return /^[\w./-]{1,120}$/.test(text) && !secretLike(text.replace(/service_role/gi, ''), false, false) ? text : 'a client-exposed variable'; };
const readJson = (file) => { try { return JSON.parse(readProjectFile(root, projectPath(root, file, { write: true }))) || {}; } catch (e) { if (e.code === 'SAFETYVIBE_BOUNDARY') throw e; return {}; } };
const configPath = file => projectPath(root, file, { write: true });
function readRc() {
  const pub = readJson(RC); const local = readJson(LOCAL);
  return { ...pub, ...Object.fromEntries(['key', 'claimToken'].filter(k => Object.hasOwn(local, k)).map(k => [k, local[k]])) };
}
function credentialFileSafe() {
  try {
    const git = args => spawnSync('git', ['-C', root, ...args], { windowsHide: true, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, maxBuffer: 65536,
      env: { ...process.env, LC_ALL: 'C', LANGUAGE: 'C' } });
    const repository = git(['rev-parse', '--is-inside-work-tree']);
    const inGit = !repository.error && !repository.signal && repository.status === 0 && repository.stdout?.trim() === 'true';
    if (inGit) {
      const trackedCheck = git(['ls-files', '--error-unmatch', '--', LOCAL]);
      if (trackedCheck.status === 0 && !trackedCheck.error && !trackedCheck.signal) {
        alert('WARNING: .safetyviberc.local.json is already tracked by Git; no credentials saved. Ignore rules cannot protect tracked credentials. Run git rm --cached -- .safetyviberc.local.json and rotate any report key or claim token committed previously.');
        return false;
      } else if (trackedCheck.status !== 1 || trackedCheck.error || trackedCheck.signal) {
        alert('Could not verify whether .safetyviberc.local.json is tracked by Git; no credentials saved. Check git ls-files --error-unmatch before retrying setup.');
        return false;
      }
    } else if (repository.error?.code !== 'ENOENT' && (repository.error || repository.signal || repository.status !== 128 || !/not a git repository/i.test(repository.stderr || ''))) {
      alert('Could not verify effective Git ignoring of .safetyviberc.local.json; no credentials saved. Check git check-ignore --no-index before retrying setup.');
      return false;
    }
    let ignore = ''; try { ignore = readFileSync(configPath('.gitignore'), 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const effective = () => { const result = git(['check-ignore', '--no-index', '--quiet', '--', LOCAL]); return result.status === 0 && !result.error && !result.signal; };
    if (!(inGit && effective()) && ignore.trimEnd().split(/\r?\n/).at(-1) !== '/' + LOCAL) {
      writeFileSync(configPath('.gitignore'), ignore + (ignore && !ignore.endsWith('\n') ? '\n' : '') + '/' + LOCAL + '\n');
    }
    if (inGit && !effective()) {
      alert('Could not verify effective Git ignoring of .safetyviberc.local.json; no credentials saved. Check git check-ignore --no-index before retrying setup.');
      return false;
    }
    return true;
  } catch {
    alert('Could not verify credential-file safety; no credentials saved. Check project permissions and Git before retrying setup.');
    return false;
  }
}
function writeRc(rc) {
  const { key, claimToken, api, ...pub } = rc;
  pub.url = normPublicUrl(pub.url || '');
  if ((key || claimToken) && !credentialFileSafe()) return 'unignored';
  try {
    if (key || claimToken) {
      writeFileSync(configPath(LOCAL), JSON.stringify({ ...(key ? { key } : {}), ...(claimToken ? { claimToken } : {}) }, null, 2) + '\n', { mode: 0o600 });
      chmodSync(configPath(LOCAL), 0o600);
    } else {
      try { unlinkSync(configPath(LOCAL)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
    writeFileSync(configPath(RC), JSON.stringify(pub, null, 2) + '\n');
  } catch { return false; }
  return 'saved';
}

function writableConfig() {
  const probe = join(root, '.safetyvibe-write-' + process.pid); let created = false;
  try {
    for (const file of [RC, LOCAL]) {
      try { if (!statSync(configPath(file)).isFile()) return false; accessSync(configPath(file), constants.W_OK); }
      catch (e) { if (e.code !== 'ENOENT') return false; }
    }
    writeFileSync(configPath(probe), '', { flag: 'wx', mode: 0o600 }); created = true;
    unlinkSync(configPath(probe)); created = false;
    return true;
  } catch { return false; }
  finally { if (created) try { unlinkSync(configPath(probe)); } catch {} }
}

function addHook() {
  let pj; let original;
  try { original = readFileSync(configPath('package.json'), 'utf8'); pj = JSON.parse(original); } catch { return 'skipped (no readable package.json)'; }
  if (!pj || typeof pj !== 'object' || Array.isArray(pj)) return 'skipped (invalid package.json)';
  if (Object.hasOwn(pj, 'scripts') && (!pj.scripts || typeof pj.scripts !== 'object' || Array.isArray(pj.scripts))) return 'skipped (invalid scripts)';
  const result = pj.scripts && Object.hasOwn(pj.scripts, 'postinstall') && typeof pj.scripts.postinstall !== 'string'
    ? { status: 'unsafe' } : withHook(pj.scripts?.postinstall || '');
  if (result.status === 'unsafe') { alert('Could not safely chain postinstall. Add this line by hand: "postinstall": "' + HOOK + '"'); return 'skipped'; }
  if (result.status === 'already there') return result.status;
  pj.scripts = { ...pj.scripts, postinstall: result.script };
  try { writeFileSync(configPath('package.json'), JSON.stringify(pj, null, /\n(\t| {4}| {2})\S/.exec(original)?.[1] || 2) + (/\r?\n$/.exec(original)?.[0] || '')); return 'added'; }
  catch { return 'could not write package.json'; }
}
function apiEndpoint() {
  const u = new URL(process.env.SAFETYVIBE_API || DEFAULT_API);
  if (u.username || u.password || u.search || u.hash || !(u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)))) throw new Error('Invalid SAFETYVIBE_API');
  return u.href.replace(/\/+$/, '') + '/report';
}
function guidance(message) {
  if (!flags.quiet) ((flags['dry-run'] || flags.json || flags.out) && !summaryOnly ? console.error : console.log)('Next: ' + message);
}
function summary(body, last, inventory) {
  const label = value => safeText(value).slice(0, 32);
  const counts = inventoryCounts(root, inventory);
  const lines = [
    'Platform: ' + label(body.platform || 'unknown'),
    `Lockfile: ${label(body.lockfile || 'none')}, ${counts.direct} direct / ${counts.total} ${body.versions_source === 'declared' ? 'declared' : 'total'} (${counts.directDev} direct dev; ${counts.confirmedDev} confirmed dev-only)`,
    'Supabase: ' + (body.supabase?.secret_key_exposed_client_side ? 'SECRET key exposed client-side (flag only)' : body.supabase ? body.supabase.key_kind + ' key (fingerprint only)' : 'none'),
    'Keys sent: 0', last,
  ];
  if (lines.join('\n').length >= 400) lines[4] = 'Connected: open your SafetyVibe dashboard';
  if (flags['dry-run'] || !flags.quiet) ((flags['dry-run'] || flags.json || flags.out) && !summaryOnly ? console.error : console.log)(lines.join('\n'));
  flushWarnings();
}
function writeBody(json) {
  if (!flags.out) return;
  const target = resolve(root, flags.out);
  const inside = (base, path) => { const r = relative(base, path); return r && r !== '..' && !r.startsWith('..' + sep) && !isAbsolute(r); };
  if (!target.endsWith('.json') || !inside(resolve(root), target) || [RC, LOCAL, 'package.json'].some(file => relative(root, target).toLowerCase() === file)) throw new Error('out');
  const base = realpathSync(root); const parent = realpathSync(dirname(target));
  if (parent !== base && !inside(base, parent)) throw new Error('out');
  writeFileSync(target, json, { flag: 'wx', mode: 0o600 });
}
async function report() {
  const setup = cmd === 'setup';
  if (!setup && !flags['dry-run'] && workspaceRoot(root) && !readRc().site) { say('SafetyVibe: workspace root; run setup in an app directory.'); return 0; }
  let destination;
  try { destination = cmd === 'inventory' ? 'Local inventory (no destination)' : apiEndpoint(); } catch { alert('Invalid SAFETYVIBE_API: use HTTPS or local HTTP.'); return 1; }
  const rc = readRc();
  const linked = typeof rc.site === 'string' && UUID.test(rc.site) && REPORT_KEY.test(rc.key || process.env.SAFETYVIBE_KEY || '');
  const rawToken = flags['claim-token'] || rc.claimToken || (!linked && process.env.SAFETYVIBE_CLAIM_TOKEN) || '';
  const token = typeof rawToken === 'string' && CLAIM_TOKEN.test(rawToken) ? rawToken : '';
  if (rawToken && !token) alert('Invalid claim token in --claim-token, SAFETYVIBE_CLAIM_TOKEN or .safetyviberc.local.json/.safetyviberc.json.');
  const givenUrl = flags.url || process.env.SAFETYVIBE_URL || rc.url || '';
  const url = normPublicUrl(givenUrl);
  if (urlNeedsCleaning(givenUrl)) alert('Removed credentials/query/fragment or unsafe path from URL; only the public URL is stored and sent');
  const body = buildReport(root, { url: givenUrl, name: flags.name || rc.name });
  const headers = { 'content-type': 'application/json', 'user-agent': 'safetyvibe-connect/' + VERSION };
  const rawKey = rc.key || process.env.SAFETYVIBE_KEY || '';
  const key = typeof rawKey === 'string' && REPORT_KEY.test(rawKey) ? rawKey : '';
  if (rawKey && !key) alert('Invalid report key in SAFETYVIBE_KEY or .safetyviberc.local.json/.safetyviberc.json.');
  if (typeof rc.site === 'string' && UUID.test(rc.site)) headers['x-safetyvibe-site'] = rc.site;
  if (rc.site && key) headers['x-safetyvibe-key'] = key;
  if (token) headers['x-safetyvibe-claim-token'] = token;
  const supabase = findSupabase(root);
  for (const name of supabase.serviceVariables) alert(`found a service-role key variable (${safeName(name)}); make sure it is never in client code`);
  for (const finding of supabase.warnings) alert(`WARNING: ${safeName(finding)} holds a Supabase secret/service_role key in client-exposed config; every visitor can read it. Rotate it in Supabase now. Only a flag is sent, never the key.`);
  const lockState = readPackages(root);
  const incompleteReason = [
    lockState.incompleteReasons?.includes('malformed') && 'some package sources could not be identified (possibly an unsupported resolution shape)',
    lockState.incompleteReasons?.includes('screened') && 'a screened value; review safety-screening warnings locally (a connector correction may be needed)',
  ].filter(Boolean).join('; ');
  if (lockState.incomplete && flags['dry-run']) alert('Inventory is incomplete: ' + incompleteReason + '. The partial package list is for local review only.');
  if (lockState.noLockfile && !flags.quiet) alert('No readable lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock); using safe package.json declarations, not resolved versions.'
    + (lockState.binaryBun ? ' Run `bun install --save-text-lockfile` to create bun.lock.' : ''));
  const projects = discoverProjects(root);
  if (projects.length) alert('Projects available (not combined): ' + projects.map(p => './' + p).join(', ') + '. Choose --project DIR or run in that directory.'
    + (body.packages.length === 0 ? ' No packages found here.' : ''));
  const json = JSON.stringify(body, null, flags.compact ? undefined : 2) + '\n';
  try { writeBody(json); } catch { alert('Could not write --out: use a new .json file inside the project root with an existing parent directory.'); return 2; }
  if (flags['dry-run']) {
    // Keep the five summary lines first; warnings follow the destination details.
    const pending = [...takeScreenWarnings(), ...warnings.splice(0)];
    summary(body, 'Dry run: nothing sent', lockState);
    guidance('Review locally with inventory --json --compact; verify receiver support before pasting.');
    if (!summaryOnly) {
      console.error(body.supabase?.secret_key_exposed_client_side ? 'A secret key is exposed in client code; only that fact is reported, never the key.' : 'Raw Supabase keys are excluded from the body; only a fingerprint is included. Known token shapes are screened in metadata; review local JSON for other sensitive values.');
      console.error(safeText(destination) + ' headers: ' + Object.keys(headers).join(', ') + ' (values hidden)');
    }
    warnings.push(...pending); flushWarnings();
    if (!summaryOnly && !flags.out) process.stdout.write(json);
    return 0;
  }
  // Declared inventories require receiver support for unchanged ranges, including
  // whitespace, and preservation across save/refresh before network reporting.
  // Keep these bodies local until compatibility has been verified.
  if (body.incomplete) {
    alert('Inventory is incomplete; nothing sent. Reason: ' + incompleteReason + '. Run with --dry-run or use inventory --json to review locally.'); return 1;
  }
  if (body.versions_source === 'declared') {
    alert('Declared-range receiver support is not verified; nothing sent. Use inventory --json --compact to review locally, or supply a supported lockfile.'); return 1;
  }
  if (!setup && !rc.site && !key && !token && !installed(root)) {
    say('SafetyVibe: no project connection or connector dependency; skipping report.'); return 0;
  }
  if (machineJson) process.stdout.write(json);
  const legacy = readJson(RC);
  const migration = ['key', 'claimToken', 'api'].some(k => Object.hasOwn(legacy, k)) || (legacy.url && legacy.url !== normPublicUrl(legacy.url));
  // An already-linked scan can use only the environment key without persisting
  // a returned key or changing connection settings, including in a read-only CI checkout.
  const envOnlyScan = !setup && linked && !rc.key && !rc.claimToken && !token && !migration
    && !flags.name && !flags.url && !flags['no-hook'] && url === normPublicUrl(rc.url || '');
  if (!envOnlyScan && !writableConfig()) { alert('SafetyVibe: project config is not writable (.safetyviberc.json / .safetyviberc.local.json); nothing sent. Run setup in a writable checkout.'); return 1; }
  if (!envOnlyScan && !credentialFileSafe()) { alert('SafetyVibe: credential-file safety could not be verified; nothing sent. Fix the checks above and retry setup.'); return 1; }
  if (migration) {
    const saved = writeRc(rc);
    if (saved !== 'saved') { alert('Could not safely save .safetyviberc.json migration; nothing sent. Review local config permissions and Git before retrying.'); return 1; }
  }
  const manager = packageManager(root);
  const runner = { npm: 'npx', pnpm: 'pnpm dlx', yarn: 'yarn dlx', bun: 'bunx' }[manager];
  if (rc.site && !key && !token) {
    alert('SafetyVibe: report key is not on this machine. Set SAFETYVIBE_KEY or get a new prompt and run ' + runner + ' safetyvibe-connect setup --claim-token <TOKEN>.');
    return setup ? 1 : 0;
  }
  let response; let b;
  const ctl = new AbortController(); let reader;
  const requested = Number(process.env.SAFETYVIBE_TIMEOUT_MS);
  const timeout = Number.isFinite(requested) && requested > 0 ? Math.min(requested, 10000) : 10000;
  const cancel = () => { ctl.abort(); if (reader) void reader.cancel().catch(() => {}); };
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => { cancel(); reject(new Error('deadline')); }, timeout); });
  try {
    const work = (async () => {
      response = await fetch(destination, { method: 'POST', headers, body: json, signal: ctl.signal, redirect: 'error' });
      reader = response.body?.getReader();
      const chunks = []; let size = 0;
      if (reader) while (true) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.byteLength; if (size > 65536) { cancel(); throw new Error('response too large'); }
        chunks.push(Buffer.from(value));
      }
      try { b = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
    })();
    work.catch(() => {});   // a late rejection after the deadline must not become an unhandled rejection
    await Promise.race([deadline, work]);
  } catch { alert('SafetyVibe: could not reach ' + safeText(new URL(destination).host) + '.'); return 1; }
  finally { clearTimeout(timer); }
  if (typeof b?.warning === 'string') alert('SafetyVibe: ' + safeText(b.warning));
  if (!response.ok) {
    if (['claim_expired', 'claim_used'].includes(b?.code)) {
      if (rc.claimToken && token === rc.claimToken) {
        delete rc.claimToken;
        if (!writeRc(rc)) alert('Could not remove claimToken from .safetyviberc.local.json/.safetyviberc.json; remove it manually before retrying.');
      }
      alert('SafetyVibe: claim token expired or already used. Get a new prompt from your dashboard.');
    }
    alert('SafetyVibe: report rejected: ' + (typeof b?.error === 'string' ? safeText(b.error) : 'HTTP ' + response.status));
    return 1;
  }
  if (!b || typeof b !== 'object' || Array.isArray(b) || typeof b.site !== 'string' || !UUID.test(b.site)) {
    alert('SafetyVibe: unexpected response from ' + safeText(new URL(destination).host) + ' (HTTP ' + response.status + ')'); return 1;
  }
  let claim = '';
  if (!b.claimed) try {
    if (typeof b.claimUrl === 'string' && !/[\x00-\x1f\x7f-\x9f]/.test(b.claimUrl)) {
      const u = new URL(b.claimUrl);
      if (u.protocol === 'https:' && !u.username && !u.password && u.origin === new URL(destination).origin) claim = u.href;   // same-origin, validated; a random claim code must not be dropped by the key screen
    }
  } catch {}
  summary(body, 'Connected: ' + (b.claimed ? 'https://dashboard.safetyvibe.eu' : claim || 'open your SafetyVibe dashboard'), lockState);
  const next = { ...rc, site: b.site, url, ...(flags.name ? { name: body.name } : {}), ...(flags['no-hook'] ? { hook: false } : {}) };
  if (typeof b.key === 'string' && REPORT_KEY.test(b.key)) next.key = b.key;
  else if (b.key) alert('Invalid report key in server response.');
  delete next.claimToken;
  const saved = envOnlyScan ? 'saved' : writeRc(next);
  if (saved !== 'saved') {
    alert('SafetyVibe: report sent; app id ' + b.site + '; could not save .safetyviberc.json here, so future reports from this folder cannot reach the same app - set SAFETYVIBE_KEY or run setup in a writable checkout');
    return 1;
  }
  const inventory = lockState;
  if (body.truncated) alert(`Only the first 5000 of ${inventory.total} packages were reported.`);
  let followup = '';
  if (setup && next.hook !== false) {
    const hook = addHook();
    if (hook === 'could not write package.json') { alert('SafetyVibe: report sent; app id ' + b.site + '; could not write package.json.'); return 1; }
    followup = 'SafetyVibe: postinstall hook ' + hook + '.';
  } else if (setup) followup = 'Re-report manually: ' + runner + ' safetyvibe-connect scan';
  // A changed package.json is always reported, even in summary mode.
  guidance(followup || 'Re-report manually: ' + runner + ' safetyvibe-connect scan');
  return 0;
}
async function main() {
  for (const file of [RC, LOCAL, '.gitignore', ...(cmd === 'setup' && !flags['dry-run'] && !flags['no-hook'] ? ['package.json'] : [])]) configPath(file);
  if (cmd === 'status') { const rc = readRc(); say(rc.site ? 'Linked to SafetyVibe app ' + safeText(rc.site) + (normPublicUrl(rc.url) ? ' (' + normPublicUrl(rc.url) + ')' : '') + '.' : 'Not linked.'); return 0; }
  return report();
}
main().then(code => { flushWarnings(); process.exit(cmd === 'scan' && code !== 2 ? 0 : code); }, e => { alert(e.code === 'SAFETYVIBE_BOUNDARY' ? 'SafetyVibe: project boundary refused an outside or linked config path; nothing sent.' : 'SafetyVibe: could not complete report.'); flushWarnings(); process.exit(cmd === 'scan' ? 0 : 1); });
