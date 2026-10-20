// safetyvibe-connect - pure helpers (no network, no writes). Tested in connect.test.mjs.
// Egress = buildReport() body: v, name?, url?, platform?, environment?, lockfile,
// versions_source, source, packages, truncated?, supabase (project_ref, host,
// key_kind + key_fingerprint OR secret_key_exposed_client_side; never keys).
// Authentication headers x-safetyvibe-site / x-safetyvibe-key /
// x-safetyvibe-claim-token, only to the default API or SAFETYVIBE_API
// (https, or http on localhost); redirects refused. Never source code or any Supabase keys.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, statSync, readdirSync, realpathSync } from 'node:fs';
import { join, dirname, sep, relative, resolve, isAbsolute } from 'node:path';

const MAX_PACKAGES = 5000;
const read = (f) => { try { return readFileSync(f, 'utf8'); } catch { return null; } };
const readJson = (f) => { const t = read(f); if (t == null) return null; try { return JSON.parse(t); } catch { return null; } };
const semver = v => typeof v === 'string' && !!screenString(v, 'package version') && /^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/.test(v);
function registryTarball(value) {
  try { const u = new URL(value); return /^https?:$/.test(u.protocol) && /\/(?:@[^/]+\/)?[^/]+\/-\/[^/]+-\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?\.tgz$/.test(decodeURIComponent(u.pathname)); } catch { return false; }
}
const registrySpec = v => typeof v === 'string' && (/^npm:(?:@[^/]+\/)?[^@]+@/.test(v) ? registrySpec(v.slice(v.lastIndexOf('@') + 1)) : /^(?:[~^<>=]*\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}(?:-[\w.-]+)?(?:\+[\w.-]+)?)(?:(?:\s+(?:-\s+)?|\s*\|\|\s*)[~^<>=]*\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}(?:-[\w.-]+)?(?:\+[\w.-]+)?)*$/.test(v.trim()));
const dependencySpecs = p => ({ ...p?.dependencies, ...p?.devDependencies, ...p?.optionalDependencies, ...p?.requires });
const nonRegistryNames = p => Object.entries(dependencySpecs(p)).filter(([, spec]) => typeof spec === 'string' && !registrySpec(spec)).map(([name]) => name);
const registryEntry = v => v && !v.link && semver(v.version) && (v.resolved == null || registryTarball(v.resolved));

// ---- lockfiles -------------------------------------------------------------
// Each parser returns [{ name, version }] for every installed package (deduped later).

export function fromPackageLock(json, { platform = process.platform, arch = process.arch } = {}) {
  const out = []; const excluded = new Set();
  const remember = p => { for (const name of nonRegistryNames(p)) excluded.add(name); };
  if (json && json.packages && typeof json.packages === 'object') {
    for (const v of Object.values(json.packages)) remember(v);
    for (const [path, v] of Object.entries(json.packages)) {
      if (!path || !registryEntry(v)) continue;
      const matches = (list, value) => !Array.isArray(list) || (!list.includes('!' + value) && (!list.some(x => !x.startsWith('!')) || list.includes(value) || list.includes('any')));
      if (v.optional && (!matches(v.os, platform) || !matches(v.cpu, arch))) continue;
      const i = path.lastIndexOf('node_modules/');
      if (i === -1 || excluded.has(path.slice(i + 'node_modules/'.length))) continue;
      out.push({ name: v.name || path.slice(i + 'node_modules/'.length), version: v.version, ...(v.dev === true ? { dev: true } : {}) });
    }
  } else if (json && json.dependencies) {                          // lockfileVersion 1
    const walk = (deps) => { for (const [n, v] of Object.entries(deps || {})) { remember(v); if (registryEntry(v)) out.push({ name: n, version: v.version, ...(v.dev === true ? { dev: true } : {}) }); walk(v && v.dependencies); } };
    walk(json.dependencies);
  }
  return out.filter(p => !excluded.has(p.name));
}

// bun.lock (text, JSONC): "packages": { "<key>": ["name@version", registry, {...}, integrity], ... }
export function fromBunLock(text) {
  const clean = String(text).replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1');
  const json = JSON.parse(clean);
  if (!json || !json.packages || typeof json.packages !== 'object' || Array.isArray(json.packages)) throw new Error('Unrecognized bun lock');
  const out = [];
  for (const v of Object.values((json && json.packages) || {})) {
    const spec = Array.isArray(v) ? v[0] : null;
    if (typeof spec !== 'string') continue;
    const at = spec.lastIndexOf('@');
    if (at <= 0) continue;
    const version = spec.slice(at + 1);
    if (semver(version) && (v[1] === '' || (typeof v[1] === 'string' && /^https?:\/\//.test(v[1]) && !/\.tgz|\.git|github/i.test(v[1])))) out.push({ name: spec.slice(0, at), version });
  }
  return out;
}

// yarn.lock v1 ("name@range":\n  version "x") and berry ("name@npm:range":\n  version: x)
export function fromYarnLock(text, manifest = {}) {
  const out = []; const seen = new Map(); const berry = /^__metadata:/m.test(text);
  const records = []; const selectors = new Map();
  for (const block of String(text).split(/(?=^\S)/m)) {
    const lines = block.split(/\r?\n/); const head = lines.shift();
    if (!head?.endsWith(':') || head.startsWith('#') || head.startsWith('__metadata')) continue;
    const specs = head.slice(0, -1).split(/,\s*/).map(s => s.replace(/^"|"$/g, ''));
    const version = /^\s+version:?\s+"?([^"\s]+)/m.exec(block)?.[1];
    const resolved = /^\s+resolved\s+["']?([^"'\s]+)/m.exec(block)?.[1];
    const resolution = /^\s+resolution:\s+"?([^"\s]+)/m.exec(block)?.[1];
    if (!semver(version) || (berry ? !/^(?:@[^/]+\/)?[^@:/]+@npm:/.test(resolution || '') : resolved != null && !registryTarball(resolved))) continue;
    const record = { specs, rows: [], dependencies: [] };
    // Yarn v1 records the exact requested selector for each dependency edge.
    for (const [, name, range] of block.matchAll(/^ {4}["']?([^\s"']+)["']?\s+["']?([^\s"']+)["']?\s*$/gm)) record.dependencies.push(name + '@' + range);
    for (const spec of new Set(specs)) {
      const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
      if (at < 1 || !(berry ? spec.slice(at + 1).startsWith('npm:') : registrySpec(spec.slice(at + 1)))) continue;
      const name = spec.slice(0, at); const id = name + '@' + version;
      if (!seen.has(id)) { const row = { name, version }; seen.set(id, row); out.push(row); }
      record.rows.push(seen.get(id)); selectors.set(spec, record);
    }
    records.push(record);
  }
  if (!berry) {
    const production = new Set();
    const queue = Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies }).map(([n, r]) => n + '@' + r);
    for (let i = 0; i < queue.length; i++) {
      const record = selectors.get(queue[i]);
      if (!record || production.has(record)) continue;
      production.add(record); queue.push(...record.dependencies);
    }
    const productionRows = new Set([...production].flatMap(r => r.rows));
    for (const [name, range] of Object.entries(manifest.devDependencies || {})) {
      const record = selectors.get(name + '@' + range);
      if (record) for (const row of record.rows) if (!productionRows.has(row)) row.dev = true;
    }
    // Transitive dev status is unknown unless the lock format records it; never
    // infer that every transitive row is dev-only from an all-dev root manifest.
  }
  return out;
}

export function declaredPackages(root) {
  const manifest = readJson(join(root, 'package.json')) || {};
  const runtime = { ...manifest.dependencies, ...manifest.optionalDependencies };
  return Object.entries({ ...manifest.devDependencies, ...runtime }).flatMap(([name, version]) => {
    if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(name) || !screenString(name, 'package name', undefined, true)
      || typeof version !== 'string' || version.length > 200 || !screenString(version, 'package version')
      || !registrySpec(version) || version.includes(':')) return [];
    return [{ ecosystem: 'npm', name, version, ...(!Object.hasOwn(runtime, name) ? { dev: true } : {}) }];
  });
}

export function inventoryCounts(root, inventory = readPackages(root)) {
  const direct = declaredPackages(root);
  return { direct: direct.length, directDev: direct.filter(p => p.dev).length,
    total: inventory.total ?? inventory.packages.length, confirmedDev: inventory.packages.filter(p => p.dev).length };
}

function workspaceGlobs(root) {
  const ws = readJson(join(root, 'package.json'))?.workspaces;
  const block = /^packages:\s*\r?\n((?:[ \t]+.*\r?\n?)*)/m.exec(read(join(root, 'pnpm-workspace.yaml')) || '')?.[1] || '';
  return [...(Array.isArray(ws) ? ws : Array.isArray(ws?.packages) ? ws.packages : []),
    ...[...block.matchAll(/^\s+-\s+['"]?([^'"\r\n]+?)['"]?\s*$/gm)].map(m => m[1])].filter(g => typeof g === 'string');
}
function matchesWorkspace(path, globs) {
  const segments = path.split('/');
  const matches = g => {
    const parts = g.replace(/^\.\//, '').replace(/\/$/, '').split('/');
    const segmentMatches = (pattern, value) => new RegExp('^' + pattern.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*') + '$').test(value);
    const match = (i, j) => i === parts.length ? j === segments.length
      : parts[i] === '**' ? match(i + 1, j) || (j < segments.length && match(i, j + 1))
      : j < segments.length && segmentMatches(parts[i], segments[j]) && match(i + 1, j + 1);
    return match(0, 0);
  };
  return globs.some(g => !g.startsWith('!') && matches(g)) && !globs.some(g => g.startsWith('!') && matches(g.slice(1)));
}

// Discovery is advice only. Never merge subprojects or silently change a linked app.
export function discoverProjects(root) {
  const globs = workspaceGlobs(root); const out = []; const queue = [{ dir: root, path: '', depth: 0 }];
  let visited = 0;
  for (let i = 0; i < queue.length && visited < 500; i++) {
    const parent = queue[i]; let entries = [];
    try { entries = readdirSync(parent.dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (++visited > 500) break;
      if (!entry.isDirectory() || entry.isSymbolicLink() || entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      const path = parent.path ? parent.path + '/' + entry.name : entry.name;
      const dir = join(parent.dir, entry.name);
      const common = /^(frontend|client|web)$|^apps\/[^/]+$/.test(path);
      const excluded = globs.some(g => g.startsWith('!') && matchesWorkspace(path, [g.slice(1)]));
      if (!excluded && (common || matchesWorkspace(path, globs)) && readJson(join(dir, 'package.json'))) {
        // Never print paths carrying key-shaped folder names.
        if (/^[A-Za-z0-9@/._ -]{1,200}$/.test(path) && screenString(path, 'project hint')) out.push(path);
      }
      if (parent.depth < 5 && (globs.length || path === 'apps')) queue.push({ dir, path, depth: parent.depth + 1 });
    }
  }
  return out.sort();
}

export function selectProject(root, hint) {
  if (!hint) return root;
  const base = realpathSync(root); const target = realpathSync(resolve(root, hint));
  const path = relative(base, target);
  if (isAbsolute(hint) || !path || path === '..' || path.startsWith('..' + sep) || isAbsolute(path)
    || !statSync(target).isDirectory() || !readJson(join(target, 'package.json'))) throw new Error('project');
  return target;
}

export function fromPnpmLock(text) {
  const out = []; const section = /^packages:\s*\r?\n([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(text)?.[1] || '';
  for (const block of section.split(/(?=^ {2}\S)/m)) {
    const head = block.split(/\r?\n/)[0];
    if (/https?:|git[+:]|github|file:|link:|workspace:/.test(head) || /\b(?:tarball|repo|directory|type):/.test(block) || !/\bintegrity:/.test(block)) continue;
    const m = /^ {2}['"]?\/?((?:@[^/\s]+\/)?[^@/\s]+)(?:@|\/)(\d+\.\d+\.\d+(?:-[\w.-]+)?)/.exec(head);
    if (m) out.push({ name: m[1], version: m[2], ...(/^ {4}dev: true\s*$/m.test(block) ? { dev: true } : {}) });
  }
  return out;
}

export function readPackages(root) {
  let list = []; let source = 'none';
  const npmLock = t => {
    const json = JSON.parse(t);
    if (!json || !['packages', 'dependencies'].some(k => json[k] && typeof json[k] === 'object' && !Array.isArray(json[k]))) throw new Error('Unrecognized npm lock');
    return fromPackageLock(json);
  };
  const tries = [
    ['package-lock.json', npmLock],
    ['npm-shrinkwrap.json', npmLock],
    ['bun.lock', fromBunLock],
    ['pnpm-lock.yaml', fromPnpmLock],
    // A shared workspace lock can contain runtime users outside this manifest.
    // Without a complete cross-workspace graph its dev-only status is unknown.
    ['yarn.lock', t => fromYarnLock(t, lockRoot === root && !workspaceGlobs(lockRoot).length ? readJson(join(root, 'package.json')) || {} : {})],
  ];
  let lockRoot = root;
  let current = root;
  for (let depth = 0; depth <= 6; depth++) {
    const workspace = matchesWorkspace(relative(current, root).split(sep).join('/'), workspaceGlobs(current));
    if (current === root || workspace) {
      lockRoot = current;
      if (workspace || tries.some(([f]) => existsSync(join(current, f))) || existsSync(join(current, 'bun.lockb'))) break;
    }
    if (existsSync(join(current, '.git')) || dirname(current) === current || depth === 6) break;
    current = dirname(current);
  }
  const manager = (readJson(join(root, 'package.json'))?.packageManager || readJson(join(lockRoot, 'package.json'))?.packageManager || '').split('@')[0];
  const preferred = { npm: ['package-lock.json', 'npm-shrinkwrap.json'], pnpm: ['pnpm-lock.yaml'], yarn: ['yarn.lock'], bun: ['bun.lock'] }[manager] || [];
  const candidates = tries.filter(([f]) => existsSync(join(lockRoot, f))).sort(([a], [b]) => Number(preferred.includes(b)) - Number(preferred.includes(a)) || statSync(join(lockRoot, b)).mtimeMs - statSync(join(lockRoot, a)).mtimeMs);
  for (const [file, parse] of candidates) {
    const t = read(join(lockRoot, file)); if (t == null) continue;
    let ok = true;
    try { list = parse(t); } catch { list = []; ok = false; }
    if (list.length) { source = file; break; }
    // Recognized locks remain authoritative when every entry was excluded; falling back
    // to installed packages could reintroduce names from non-registry sources.
    if (ok && (/\.json$|^bun\.lock$/.test(file) || (file === 'pnpm-lock.yaml' && (/^packages:/m.test(t) || /^lockfileVersion:/m.test(t) && /^importers:/m.test(t))) || (file === 'yarn.lock' && /^(?:__metadata:|# yarn lockfile v1|\S.*:\s*$)/m.test(t)))) { source = file; break; }
  }
  // No node_modules fallback. Only safe registry ranges declared in this project's
  // manifest may supplement an absent/unusable lock, never a recognized empty lock.
  const missing = source === 'none' ? { noLockfile: true, ...(existsSync(join(lockRoot, 'bun.lockb')) || existsSync(join(root, 'bun.lockb')) ? { binaryBun: true } : {}) } : {};
  const seen = new Map(); const pkgs = [];
  for (const p of list) {
    const k = p.name + '@' + p.version;
    // Registry versions only. git/file/link/http specs can carry tokens or local paths: never sent.
    const safeName = screenString(p.name, 'package name', undefined, true);
    const safeVersion = screenString(p.version, 'package version');
    if (!safeName || !safeVersion) continue;
    if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(p.name) || !/^\d+\.\d+\.\d+[\w.+-]{0,40}$/.test(String(p.version))) continue;
    if (seen.has(k)) { if (p.dev !== true) delete seen.get(k).dev; continue; }
    const row = { ecosystem: 'npm', name: p.name, version: p.version, ...(p.dev === true ? { dev: true } : {}) };
    seen.set(k, row); pkgs.push(row);

  }
  const selected = source === 'none' ? declaredPackages(root) : pkgs;
  return { packages: selected.slice(0, MAX_PACKAGES), source, ...missing, ...(selected.length > MAX_PACKAGES ? { total: selected.length, truncated: true } : {}) };
}

// ---- Supabase (project URL + PUBLIC key only) ------------------------------
function jwtPayload(value) {
  if (typeof value !== 'string' || value.length > 2000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const raw = Buffer.from(value.split('.')[1], 'base64url').toString('utf8');
    // Tokenize complete strings so quoted text inside a value cannot become a key.
    const keys = [...raw.matchAll(/"(?:[^"\\]|\\.)*"/g)]
      .filter(m => /^\s*:/.test(raw.slice(m.index + m[0].length))).map(m => JSON.parse(m[0]));
    if (new Set(keys).size !== keys.length) return { role: 'rejected' };
    const p = JSON.parse(raw); return p && typeof p === 'object' && !Array.isArray(p) ? p : null; } catch { return null; }
}
export function publicKeyKind(value) {
  if (typeof value !== 'string' || /sb_secret_|[\s#'"`]/i.test(value)) return null;
  if (/^sb_publishable_[A-Za-z0-9_-]{8,200}$/.test(value)) return 'publishable';
  const payload = jwtPayload(value);
  const claims = new Set(['iss', 'ref', 'role', 'iat', 'exp', 'nbf', 'aud', 'sub']);
  return payload?.role === 'anon'
    && (!Object.hasOwn(payload, 'iss') || ['supabase', 'supabase-demo'].includes(payload.iss))
    && (!Object.hasOwn(payload, 'ref') || (typeof payload.ref === 'string' && /^[a-z0-9]{10,40}$/.test(payload.ref)))
    && Object.entries(payload).every(([key, value]) => claims.has(key)
      && (typeof value === 'number' || (typeof value === 'string' && value.length <= 100 && !/sb_secret_|svk_|eyJ/i.test(value)))) ? 'anon' : null;
}
export function keyKind(value) {
  const kind = publicKeyKind(value);
  if (kind) return kind;
  const payload = jwtPayload(value);
  return /sb_secret_/i.test(String(value || '')) || (payload && typeof payload.role === 'string' && payload.role !== 'anon') ? 'secret' : 'unknown';
}
export function parseEnv(text) {
  const env = {};
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(/^\s*(?:export\s+)?([\w.-]+)\s*=\s*(.*)$/);
    if (!m) continue;
    let value = m[2]; const quote = value[0];
    if (["'", '"', '`'].includes(quote)) {
      let end = 1;
      for (; ; end++) {
        if (end >= value.length) {
          if (i + 1 === lines.length) break;
          value += '\n' + lines[++i];
        }
        if (quote === '"' && value[end] === '\\') { end++; continue; }
        if (value[end] === quote) break;
      }
      if (end >= value.length) continue;
      env[m[1]] = value.slice(1, end);
    } else env[m[1]] = value.split('#')[0].trim();
  }
  return env;
}

// Only client-exposed variable names (bundled into the browser build by these prefixes); server-only
// names such as SUPABASE_URL / SUPABASE_ANON_KEY are never read.
const CLIENT_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'EXPO_PUBLIC_', 'PUBLIC_', 'REACT_APP_', 'NUXT_PUBLIC_'];
const URL_VARS = CLIENT_PREFIXES.map(p => p + 'SUPABASE_URL');
const KEY_VARS = CLIENT_PREFIXES.flatMap(p => [p + 'SUPABASE_PUBLISHABLE_KEY', p + 'SUPABASE_ANON_KEY']);
// Full shapes only: a bare prefix is validation code, but a full key in a comparison,
// comment or larger literal is still shipped to visitors. Bounded JWT candidates keep
// scanning linear even for large minified files with malformed/unterminated literals.
const secretTokens = /sb_secret_[A-Za-z0-9_-]{20,}|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{1,2000}\.[A-Za-z0-9_-]{1,2000}\.[A-Za-z0-9_-]{1,2000}/g;
function exposedSupabaseSecret(value, keySlot = false) {
  if (typeof value !== 'string') return false;
  for (const [token] of value.matchAll(secretTokens)) {
    if (token.startsWith('sb_secret_')) return true;
    const role = jwtPayload(token)?.role;
    if (role === 'service_role' || (keySlot && typeof role === 'string' && role !== 'anon')) return true;
  }
  return false;
}
// A value assigned to a publishable/anon key name must be public: any other JWT role there is a secret.
const secretInKeySlot = value => exposedSupabaseSecret(value, true);

// Only clearly client-side source files: what the browser bundle already ships to every visitor.
const SERVER_PATH = /(^|\/)(server|api|functions)\/|(^|\/)app\/api\/|(^|\/)pages\/api\/|(^|\/)supabase\/functions\/|(^|\/)netlify\/functions\/|(^|\/)middleware\.[cm]?[jt]sx?$|\.server\.[cm]?[jt]sx?$/i;
export function clientSource(path, text) {
  if (SERVER_PATH.test(String(path).split('\\').join('/'))) return false;
  // Any quoted 'server-only' or "use server" anywhere (comments, spacing or syntax tricks included) marks
  // the file as server code. Excluding a client file by mistake is the safe direction.
  return !/['"`]server-only['"`]/.test(text) && !/['"`]use server['"`]/.test(text);
}
export function findSupabase(root, procEnv = process.env) {
  const env = {}; const warnings = new Set(); const serviceVariables = new Set();
  const collect = (values, file = false) => {
    for (const k of Object.keys(values)) {
      // Server-side env vars are normal; only names written into .env* files get the local reminder.
      if (file && /SERVICE_ROLE|(?:^|_)SUPABASE_SERVICE_KEY$/i.test(k)) serviceVariables.add(k);
      if (!CLIENT_PREFIXES.some(p => k.startsWith(p))) continue;
      const value = values[k];
      if (KEY_VARS.includes(k) ? secretInKeySlot(value) : exposedSupabaseSecret(value)) warnings.add(k);
      if (value) env[k] = value;
    }
  };
  for (const f of ['.env', '.env.local', '.env.production', '.env.production.local']) collect(parseEnv(read(join(root, f))), true);
  collect(procEnv);
  let url = URL_VARS.map(k => env[k]).find(value => /^https:\/\/[a-z0-9-]+\.supabase\.(co|in)\/?$/i.test(value || '')) || '';
  let key = KEY_VARS.map(k => env[k]).find(value => publicKeyKind(value)) || '';
  // Scan every allowed client file even when environment config is complete.
  for (const f of ['src/integrations/supabase/client.ts', 'src/integrations/supabase/client.js', 'src/lib/supabase.ts', 'src/lib/supabase.js', 'lib/supabase.ts', 'utils/supabase.ts']) {
    const t = read(join(root, f)); if (!t || !clientSource(f, t)) continue;
    url = url || ((t.match(/["'`](https:\/\/[a-z0-9-]+\.supabase\.co)["'`]/i) || [])[1] || '');
    // One forward token pass; no growing prefix/suffix slices and no quote-pair drift.
    if (exposedSupabaseSecret(t)) warnings.add(f);
    for (const match of t.matchAll(/\b([\w]*(?:PUBLISHABLE|ANON)_KEY)\s*=\s*["'`]([^"'`]+)["'`]/gi)) {
      if (secretInKeySlot(match[2])) warnings.add(f);
      if (!key && publicKeyKind(match[2])) key = match[2];
    }
  }
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.(co|in)\/?$/i.test(url)) url = '';
  const kind = key ? keyKind(key) : 'none';
  // Never send anything that isn't provably a public key.
  if (!publicKeyKind(key)) key = '';
  return { url: url.replace(/\/$/, ''), key, kind, warnings: [...warnings], serviceVariables: [...serviceVariables] };
}

// ---- app identity ------------------------------------------------------------
const HOSTS = { 'lovable.app': 'Lovable', 'replit.app': 'Replit', 'repl.co': 'Replit', 'bolt.host': 'Bolt', 'base44.app': 'Base44', 'emergent.host': 'Emergent', 'emergentagent.com': 'Emergent', 'softgen.ai': 'Softgen', 'softgen.dev': 'Softgen', 'lp.dev': 'Leap', 'vercel.app': 'Vercel', 'netlify.app': 'Netlify', 'run.app': 'Google Cloud Run' };
export function detectPlatform(root, procEnv = process.env, url = '') {
  const pj = readJson(join(root, 'package.json')) || {};
  const deps = { ...pj.dependencies, ...pj.devDependencies };
  if (deps['lovable-tagger'] || existsSync(join(root, '.lovable'))) return 'Lovable';
  if (existsSync(join(root, '.replit'))) return 'Replit';
  for (const [marker, label] of Object.entries({ '.bolt': 'Bolt', '.emergent': 'Emergent', '.softgen': 'Softgen', '.leap': 'Leap', '.rocket': 'Rocket', '.v0': 'v0' })) if (existsSync(join(root, marker))) return label;
  if (String(pj.name || '').toLowerCase().replace(/^@[^/]+\//, '') === 'softgen-starter') return 'Softgen';
  for (const dir of [root, join(root, 'frontend')]) for (const file of ['.env', '.env.local', '.env.production']) {
    for (const value of Object.values(parseEnv(read(join(dir, file))))) {
      try { const u = new URL(value); if (/^https?:$/.test(u.protocol) && /\.(emergentagent\.com|emergent\.host)$/.test(u.hostname)) return 'Emergent'; } catch {}
    }
  }
  if (deps['@base44/sdk']) return 'Base44';
  if (Object.hasOwn(readJson(join(root, 'metadata.json')) || {}, 'requestFramePermissions') || (pj.name === 'react-example' && deps['@google/genai']) || ['ts', 'js', 'mjs', 'mts'].some(ext => /process\.env\.GEMINI_API_KEY/.test(read(join(root, 'vite.config.' + ext)) || ''))) return 'Google AI Studio';
  try { const host = new URL(url).hostname; for (const [suffix, label] of Object.entries(HOSTS)) if (host.endsWith('.' + suffix)) return label; } catch {}
  if (procEnv.REPL_ID) return 'Replit';
  if (procEnv.VERCEL) return 'Vercel';
  if (procEnv.NETLIFY) return 'Netlify';
  return '';
}
const TEMPLATES = new Set('softgen-starter my-react-app create-react-app starter template workspace frontend backend client web app project src home repl code dev-server react-example vite-project vite-react-shadcn-ts tanstack-start-ts vite-react-typescript-starter rest-express my-app react-app nextjs next-app nextjs-app my-v0-project'.split(' '));
TEMPLATES.add('');
// Real JWTs start with eyJ (base64 of {"); plain dotted names like notes.example.com stay allowed.
export function screenNormalized(value) {
  let text = String(value || '');
  for (let i = 0; i < 3; i++) {
    const decoded = text.replace(/(?:%[0-9a-f]{2})+/gi, run => { try { return decodeURIComponent(run); } catch { return run; } });
    if (decoded === text) break;
    text = decoded;
  }
  const glyphs = { \u0430:'a', \u0435:'e', \u043e:'o', \u0440:'p', \u0441:'c', \u0445:'x', \u0443:'y', \u0456:'i', \u0455:'s', \u0458:'j', \u043a:'k', \u043c:'m', \u043d:'h', \u0442:'t', \u0432:'b', \u03bf:'o', \u03b1:'a', \u03b5:'e', \u03b9:'i', \u03ba:'k', \u03bd:'v', \u03c1:'p', \u03c4:'t', \u03c5:'y', \u03c7:'x' };
  // Decompose first so accents composed onto letters (e + U+0301 -> U+00E9) are stripped too, then recompose.
  return text.normalize('NFKD').replace(/[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, '').normalize('NFKC').replace(/[\u0430 \u0435 \u043e \u0440 \u0441 \u0445 \u0443 \u0456 \u0455 \u0458 \u043a \u043c \u043d \u0442 \u0432 \u03bf \u03b1 \u03b5 \u03b9 \u03ba \u03bd \u03c1 \u03c4 \u03c5 \u03c7]/giu, c => glyphs[c.toLowerCase()] || c);
}
export function secretLike(value, packageName = false, credentials = true) {
  if (typeof value !== 'string') return false;
  return [value, screenNormalized(value)].some(v => {
    // eyJ is case-sensitive (base64 of '{"'): lowercase "eyj" occurs in ordinary words (honeyjar, journeyjs).
    if (/sb_publishable_|sb_secret_|sk_live_|sk_test_|sk-ant-|sk-proj-|rk_live_|service_role|svk_/i.test(v) || /eyJ/.test(v)) return true;
    // Generic secret-key shapes (sk_<random>, sk-<random>) with no separators in the random part.
    if (/sk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}/i.test(v)) return true;
    if (credentials && (/[a-z][a-z0-9+.-]*:\/\/[^\s/?#]*@/i.test(v) || /(?:^|[?&])(?:apikey|api_key|access_token|token|key|sig|signature|secret|password)=/i.test(v))) return true;
    // Within a run, a separator-free piece of >= 32 characters, or >= 16 mixing letters and digits, is key
    // material; hyphenated words and paths ("some-long-path/another-segment") are not. Real npm package
    // names are exempt from this long-run rule only, never from the key prefixes above.
    if (packageName && /^(@[\w.-]+\/)?[\w.-]{1,214}$/.test(value)) return false;
    return (v.match(/[A-Za-z0-9+/_=-]{40,}/g) || []).some(run => run.split(/[-/_+=]/)
      .some(piece => piece.length >= 32 || (piece.length >= 16 && /[a-z]/i.test(piece) && /\d/.test(piece))));
  });
}
// Screening warnings are collected (deduplicated) and printed by the CLI after the summary.
const screenWarnings = new Set();
export function takeScreenWarnings() { const list = [...screenWarnings]; screenWarnings.clear(); return list; }
export function screenString(value, field, warn = message => screenWarnings.add(message), packageName = false) {
  if (typeof value !== 'string') return '';
  if (!secretLike(value, packageName, false)) return value;
  warn('Dropped ' + field + ': it looked like a key.');
  return '';
}
export function appName(root, explicit = '', url = '') {
  let host = ''; try { host = new URL(url).hostname; if (Object.keys(HOSTS).some(s => host.endsWith('.' + s))) host = host.split('.')[0]; } catch {}
  for (const candidate of [explicit, host, readJson(join(root, 'package.json'))?.name]) {
    const raw = String(candidate || '').trim();
    if (!screenString(raw, 'name')) { if (raw) return ''; continue; }
    const n = raw.replace(/[^A-Za-z0-9 @/._-]/g, '').trim();
    if (n && (!screenString(n, 'name') || !screenString(n.slice(0, 80), 'name'))) return '';
    if (n && !TEMPLATES.has(n.toLowerCase().replace(/^@[^/]+\//, '').replace(/_/g, '-'))) return n.slice(0, 80);
  }
  return '';
}
export function packageManager(root, env = process.env) {
  const field = readJson(join(root, 'package.json'))?.packageManager?.split('@')[0];
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(field)) return field;
  const source = readPackages(root).source;
  if (source.startsWith('pnpm')) return 'pnpm';
  if (source.startsWith('yarn')) return 'yarn';
  if (source.startsWith('bun') || existsSync(join(root, 'bun.lockb'))) return 'bun';
  if (source.endsWith('.json')) return 'npm';
  return /^(pnpm|yarn|bun)\//.exec(env.npm_config_user_agent || '')?.[1] || 'npm';
}
export const HOOK = 'safetyvibe-connect scan --quiet || exit 0';
export function withHook(current = '') {
  const cur = String(current).trim();
  const base = cur.replace(/\s*&&\s*\(?safetyvibe-connect scan(?: --quiet)?(?: \|\| exit 0)?\)?$/, '').replace(/^\(?safetyvibe-connect scan(?: --quiet)?(?: \|\| exit 0)?\)?$/, '').trim();
  if (/^[&|;]|[&|;\\^]$|[\r\n`<>#;$%!]|\$\(|[()]/.test(base) || /(?<![&|])[&|](?![&|])/.test(base) || /['"]/.test(base)) return { script: current, status: 'unsafe' };
  const script = base ? base + ' && (' + HOOK + ')' : HOOK;
  return { script, status: script === cur ? 'already there' : 'added' };
}

function publicUrl(given) {
  if (!screenString(given, 'url')) return { url: '', cleaning: Boolean(given) };
  try {
    const u = new URL(String(given));
    if (!['http:', 'https:'].includes(u.protocol)) return { url: '', cleaning: false };
    if (/sb_|svk_|eyJ/i.test(u.hostname)) return { url: '', cleaning: true };
    const keep = /^(\/[A-Za-z0-9._~-]{1,64}){0,8}\/?$/.test(u.pathname)
      && u.pathname.split('/').every(segment => segment.length <= 40 && !/sb_|svk_|eyJ/i.test(segment));
    return { url: u.origin + (keep && u.pathname !== '/' ? u.pathname : ''),
      cleaning: Boolean(u.username || u.password || u.search || u.hash || !keep) };
  } catch { return { url: '', cleaning: false }; }
}
export function normPublicUrl(given) { return publicUrl(given).url; }
export function urlNeedsCleaning(given) { return publicUrl(given).cleaning; }

export function buildReport(root, opts = {}, procEnv = process.env) {
  const { packages, source, truncated } = readPackages(root);
  const url = normPublicUrl(opts.url || procEnv.SAFETYVIBE_URL || '');
  const sb = findSupabase(root, procEnv);
  const host = sb.url ? screenString(new URL(sb.url).host, 'supabase host') || null : null;
  const project_ref = host && /^([a-z0-9]{20})\.supabase\.co$/.exec(host)?.[1] || null;
  const supabase = sb.warnings.length ? { project_ref, host, secret_key_exposed_client_side: true }
    : sb.url && sb.key ? { project_ref, host, key_kind: sb.kind, key_fingerprint: createHash('sha256').update(sb.key, 'utf8').digest('hex').slice(0, 8) } : null;
  const rawEnvironment = String(opts.environment || procEnv.SAFETYVIBE_ENV || (procEnv.NODE_ENV === 'production' ? 'production' : ''));
  const environment = rawEnvironment.replace(/[^A-Za-z0-9_-]/g, '');
  return Object.fromEntries(Object.entries({
    v: 1,
    name: appName(root, opts.name, url),
    url,
    platform: screenString(detectPlatform(root, procEnv, url), 'platform'),
    environment: screenString(rawEnvironment, 'environment') && screenString(environment, 'environment') ? environment.slice(0, 20) : '',
    lockfile: source,
    versions_source: source === 'none' ? 'declared' : 'lockfile',
    source: "connector",
    packages,
    ...(truncated ? { truncated: true } : {}),
    supabase,
  }).filter(([, value]) => value !== ''));
}
