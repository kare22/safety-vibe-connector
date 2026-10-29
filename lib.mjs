// safetyvibe-connect - pure helpers (no network, no writes). Tested in test/*.test.mjs.
// Egress = buildReport() body: v, name?, url?, platform?, environment?, lockfile,
// versions_source, source, packages, truncated?, incomplete? (local only), supabase (project_ref, host,
// key_kind + key_fingerprint OR secret_key_exposed_client_side; never keys).
// Authentication headers x-safetyvibe-site / x-safetyvibe-key /
// x-safetyvibe-claim-token, only to the default API or SAFETYVIBE_API
// (https, or http on localhost); redirects refused. Never source code or any Supabase keys.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, statSync, readdirSync, realpathSync, lstatSync } from 'node:fs';
import { join, dirname, sep, relative, resolve, isAbsolute } from 'node:path';

const MAX_PACKAGES = 5000;
const within = (base, target) => { const path = relative(base, target); return !isAbsolute(path) && path !== '..' && !path.startsWith('..' + sep); };
const boundaryError = () => Object.assign(new Error('Project boundary refused an outside or linked config path.'), { code: 'SAFETYVIBE_BOUNDARY' });
// Ancestor workspace metadata/locks use their own explicit boundary. Every other
// read stays inside the selected project; config writes also reject internal links.
export function projectPath(root, file, { write = false } = {}) {
  const lexical = resolve(root); const base = realpathSync(lexical); const target = resolve(lexical, file);
  if (!within(lexical, target)) throw boundaryError();
  let current = lexical;
  for (const part of relative(lexical, target).split(sep).filter(Boolean)) {
    current = join(current, part);
    let info; try { info = lstatSync(current); } catch (e) { if (e.code === 'ENOENT') break; throw e; }
    if ((write && (info.isSymbolicLink() || (current === target && info.isFile() && info.nlink > 1)))
      || !within(base, realpathSync(current))) throw boundaryError();
  }
  return target;
}
export function readProjectFile(root, file) {
  try { return readFileSync(projectPath(root, file), 'utf8'); }
  catch (e) { if (e.code === 'SAFETYVIBE_BOUNDARY') throw e; return null; }
}
const read = (f, root) => readProjectFile(root, f);
const readJson = (f, root) => { const t = read(f, root); if (t == null) return null; try { return JSON.parse(t); } catch { return null; } };
const projectExists = (root, file) => existsSync(projectPath(root, file));
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[\dA-Za-z-]*[A-Za-z-][\dA-Za-z-]*)(?:\.(?:0|[1-9]\d*|[\dA-Za-z-]*[A-Za-z-][\dA-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const semver = v => typeof v === 'string' && !!screenString(v, 'package version') && SEMVER.test(v);
function markIncomplete(rows, version, category) {
  rows.incomplete = true;
  const reason = category || (typeof version === 'string' && !screenString(version, 'package version') ? 'screened' : 'malformed');
  rows.incompleteReasons = [...new Set([...(rows.incompleteReasons || []), reason])];
}
const identity = value => {
  if (typeof value !== 'string') return {};
  const at = value.indexOf('@', value.startsWith('@') ? 1 : 0);
  return at < 1 ? { name: value } : { name: value.slice(0, at), spec: value.slice(at + 1) };
};
function unpatch(value) {
  if (typeof value !== 'string' || !value.startsWith('patch:')) return value;
  try { return identity(decodeURIComponent(value.slice(6).split('#')[0])).spec; } catch { return undefined; }
}
function sourceReason(value, declared = false) {
  if (typeof value !== 'string') return null;
  if (value.startsWith('patch:')) return sourceReason(unpatch(value), declared);
  if (/^(?:git[+:@]|ssh:|github:|gitlab:|bitbucket:|file:|link:|portal:|workspace:|exec:)/i.test(value)) return 'source protocol';
  if (declared && /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(value)) return 'git shorthand';
  if (declared && /^https?:\/\//i.test(value)) return 'declared URL dependency';
  return null;
}
// All lock formats use this decision. Private registries own their delivery
// paths; only canonical public registries impose a tarball route contract.
export function classifyPackageSource({ name, version, specs = [], resolution, link = false, malformed = false }) {
  const excluded = reason => ({ status: 'excluded', reason });
  if (link) return excluded('workspace link');
  for (const spec of specs) { const reason = sourceReason(spec, true); if (reason) return excluded(reason); }
  const protocol = sourceReason(resolution);
  if (protocol) return excluded(protocol);
  if (typeof resolution === 'string' && resolution.startsWith('patch:') && registrySpec(unpatch(resolution))) resolution = undefined;
  let u, path;
  if (resolution !== undefined) {
    try {
      if (typeof resolution !== 'string' || !/^https?:\/\//i.test(resolution)) throw new Error();
      u = new URL(resolution); path = decodeURIComponent(u.pathname);
      const host = u.hostname.toLowerCase().replace(/\.$/, '');
      u.hostname = host;
      if ((host === 'raw.githubusercontent.com' || host === 'gist.github.com' || host === 'gist.githubusercontent.com')
        || ((host === 'github.com' || host === 'codeload.github.com') && /\/(?:archive|tarball|zipball|tar\.gz|zip)(?:\/|$)|\.(?:tgz|tar\.gz|zip)$|\.git\/?$/i.test(path))
        || (host === 'gitlab.com' && /\/-\/archive\//.test(path))
        || (host === 'bitbucket.org' && /\/get\//.test(path))) return excluded('known source-host archive');
    } catch { return { status: 'incomplete', reason: 'malformed resolution' }; }
  }
  if (typeof name === 'string' && !screenString(name, 'package name', undefined, true)
    || typeof version === 'string' && !screenString(version, 'package version')) return { status: 'incomplete', reason: 'screened metadata' };
  if (malformed || !semver(version) || typeof name !== 'string' || !/^(@[\w.-]+\/)?[\w.-]+$/.test(name)
    || specs.some(spec => spec !== undefined && typeof spec !== 'string')) return { status: 'incomplete', reason: 'malformed metadata' };
  if (u && /^(?:registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com)$/.test(u.hostname)) {
    const canonical = /^\/((?:@[^/]+\/)?[^/]+)\/-\/(@[^/]+\/)?([^/]+)\.tgz$/.exec(path);
    const download = u.hostname === 'npm.pkg.github.com' && /^\/download\/((?:@[^/]+\/)?[^/]+)\/([^/]+)\/([a-f\d]+)$/i.exec(path);
    if (u.port || !(canonical && canonical[1] === name && (!canonical[2] || name.startsWith(canonical[2])) && canonical[3] === name.split('/').at(-1) + '-' + version
      || download && download[1] === name && download[2] === version)) return { status: 'incomplete', reason: 'invalid canonical registry route' };
  }
  return { status: 'reported', name, version };
}
function addClassified(out, input, extra = {}, key) {
  const decision = classifyPackageSource(input);
  if (!out.classifications) Object.defineProperty(out, 'classifications', { value: [] });
  // Local accounting only: reasons and row keys never enter the report body.
  out.classifications.push({ key, ...decision });
  if (decision.status === 'reported') { const row = { name: decision.name, version: decision.version, ...extra }; out.push(row); return row; }
  if (decision.status === 'incomplete') markIncomplete(out, input.version, decision.reason === 'screened metadata' ? 'screened' : undefined);
}
const registrySpec = v => typeof v === 'string' && (/^npm:/.test(v) ? !!identity(v.slice(4)).name && (!identity(v.slice(4)).spec || registrySpec(identity(v.slice(4)).spec)) : /^[A-Za-z][A-Za-z0-9._-]*$/.test(v) || /^(?:[~^<>=]*\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}(?:-[\w.-]+)?(?:\+[\w.-]+)?)(?:(?:\s+(?:-\s+)?|\s*\|\|\s*)[~^<>=]*\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}(?:-[\w.-]+)?(?:\+[\w.-]+)?)*$/.test(v.trim()));
const dependencySpecs = p => ({ ...p?.dependencies, ...p?.devDependencies, ...p?.optionalDependencies, ...p?.requires });
const relevantSpecs = specs => {
  const registry = specs.filter(spec => registrySpec(unpatch(spec)));
  return registry.length ? registry : specs;
};

// ---- lockfiles -------------------------------------------------------------
// Each parser returns [{ name, version }] for every installed package (deduped later).

export function fromPackageLock(json, { manifest = {} } = {}) {
  if (!json?.packages && json?.dependencies) {
    const packages = { '': manifest };
    const walk = (deps, parent = '') => { for (const [name, value] of Object.entries(deps || {})) {
      const path = parent + 'node_modules/' + name;
      packages[path] = { ...value, dependencies: value?.requires || {} };
      walk(value?.dependencies, path + '/');
    } };
    walk(json.dependencies);
    return fromPackageLock({ packages });
  }
  const out = [];
  const add = (name, v, specs, key) => {
    const alias = typeof v?.version === 'string' && v.version.startsWith('npm:') ? identity(v.version.slice(4)) : null;
    addClassified(out, { name: alias?.name || v?.name || name, version: alias?.spec || v?.version,
      specs: [...specs, ...(alias ? [] : [v?.version])], resolution: v?.resolved, link: v?.link === true }, v?.dev === true ? { dev: true } : {}, key);
  };
  if (json && json.packages && typeof json.packages === 'object') {
    const edges = new Map();
    for (const [parent, value] of Object.entries({ ...json.packages, '': { ...manifest, ...json.packages[''] } })) {
      for (const [name, spec] of Object.entries(dependencySpecs(value))) {
        let base = parent;
        for (;;) {
          const path = (base ? base + '/' : '') + 'node_modules/' + name;
          if (Object.hasOwn(json.packages, path)) { if (!edges.has(path)) edges.set(path, []); edges.get(path).push(spec); break; }
          if (!base) break;
          const i = base.lastIndexOf('/'); base = i < 0 ? '' : base.slice(0, i);
          if (base.endsWith('node_modules')) base = base.slice(0, -12).replace(/\/$/, '');
        }
      }
    }
    for (const [path, v] of Object.entries(json.packages)) {
      if (!path || !path.includes('node_modules/')) continue;
      const i = path.lastIndexOf('node_modules/');
      const specs = edges.get(path) || [];
      // A remote edge is satisfied only by its exact resolved URL. Such an
      // installation remains a source even when a range also accepts its version.
      // Unmatched source edges cannot suppress a shared registry installation.
      const satisfiedSources = specs.filter(spec => sourceReason(spec, true)
        && (spec === v?.resolved || spec === v?.version));
      add(path.slice(i + 13), v, [...satisfiedSources, ...relevantSpecs(specs)], path);
    }
    const installed = new Set(Object.keys(json.packages).map(path => path.slice(path.lastIndexOf('node_modules/') + 13)));
    for (const [name, spec] of Object.entries({ ...json.packages['']?.dependencies, ...json.packages['']?.devDependencies })) {
      if (registrySpec(spec) && !installed.has(name)) markIncomplete(out);
    }
  }
  return out;
}

// bun.lock (text, JSONC): "packages": { "<key>": ["name@version", registry, {...}, integrity], ... }
export function fromBunLock(text) {
  const clean = String(text).replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1');
  const json = JSON.parse(clean);
  if (!json || !json.packages || typeof json.packages !== 'object' || Array.isArray(json.packages)) throw new Error('Unrecognized bun lock');
  const out = [];
  const edges = new Map();
  const remember = (parent, declarations) => {
    for (const [name, spec] of Object.entries(dependencySpecs(declarations))) {
      let base = parent;
      for (;;) {
        const path = (base ? base + '/' : '') + name;
        if (Object.hasOwn(json.packages, path)) {
          if (!edges.has(path)) edges.set(path, []);
          edges.get(path).push(spec); break;
        }
        if (!base) break;
        base = base.replace(/\/+$/, '').replace(/(?:^|\/)(?:@[^/]+\/)?[^/]+$/, '');
      }
    }
  };
  for (const [path, workspace] of Object.entries(json.workspaces || {})) {
    const installed = Object.entries(json.packages).filter(([, v]) => Array.isArray(v) && identity(v[0]).spec === 'workspace:' + path);
    if (!path) remember('', workspace);
    else for (const [key] of installed) remember(key, workspace);
  }
  for (const [key, value] of Object.entries(json.packages)) if (Array.isArray(value)) remember(key, value[2]);
  for (const [key, v] of Object.entries(json.packages)) {
    const spec = Array.isArray(v) ? v[0] : null;
    if (typeof spec !== 'string') { addClassified(out, { malformed: true }, {}, key); continue; }
    const { name, spec: version } = identity(spec);
    addClassified(out, { name, version, specs: [version, ...relevantSpecs(edges.get(key) || [])], resolution: v[1] === '' ? undefined : v[1], malformed: v[1] === undefined }, {}, key);
  }
  return out;
}

// yarn.lock v1 ("name@range":\n  version "x") and berry ("name@npm:range":\n  version: x)
export function fromYarnLock(text, manifest = {}) {
  const out = []; const seen = new Map(); const berry = /^__metadata:/m.test(text);
  const records = []; const selectors = new Map();
  for (const block of String(text).split(/(?=^\S)/m)) {
    const lines = block.split(/\r?\n/); const head = lines.shift();
    if (!head?.trim() || head.startsWith('#') || head.startsWith('__metadata')) continue;
    if (!head.endsWith(':')) { addClassified(out, { malformed: true }, {}, head); continue; }
    const specs = head.slice(0, -1).split(/,\s*/).map(s => s.replace(/^"|"$/g, ''));
    const version = /^\s+version:?\s+"?([^"\s]+)/m.exec(block)?.[1];
    const resolvedLine = /^\s+resolved(?:[ \t]+(.*))?$/m.exec(block);
    const resolved = resolvedLine ? (resolvedLine[1] || '').trim().replace(/^["']|["']$/g, '') : undefined;
    const resolution = /^\s+resolution:\s+"?([^"\s]+)/m.exec(block)?.[1];
    const registryName = spec => {
      const item = identity(spec); const range = unpatch(item.spec);
      return typeof range === 'string' && range.startsWith('npm:') && identity(range.slice(4)).name || item.name;
    };
    const record = { specs, rows: [], dependencies: [] };
    // Yarn v1 records the exact requested selector for each dependency edge.
    for (const [, name, range] of block.matchAll(/^ {4}["']?([^\s"']+)["']?\s+["']?([^\s"']+)["']?\s*$/gm)) record.dependencies.push(name + '@' + range);
    for (const spec of new Set(specs)) {
      const locator = identity(resolution); const protocol = unpatch(locator.spec);
      const name = berry ? locator.name : registryName(spec);
      const row = addClassified(out, { name, version, specs: [identity(spec).spec, ...(berry ? [protocol] : [])],
        resolution: berry ? (protocol?.startsWith('npm:') ? undefined : protocol) : resolved,
        malformed: !identity(spec).spec || (berry && (!resolution || !protocol || !(protocol.startsWith('npm:') || sourceReason(protocol, true)))) }, {}, spec);
      if (!row) continue;
      const id = name + '@' + version;
      if (!seen.has(id)) seen.set(id, row); else out.pop();
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
  const manifest = readJson(join(root, 'package.json'), root) || {};
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
  const ws = readJson(join(root, 'package.json'), root)?.workspaces;
  const block = /^packages:\s*\r?\n((?:[ \t]+.*\r?\n?)*)/m.exec(read(join(root, 'pnpm-workspace.yaml'), root) || '')?.[1] || '';
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
    try { entries = readdirSync(projectPath(root, parent.dir), { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (++visited > 500) break;
      if (!entry.isDirectory() || entry.isSymbolicLink() || entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      const path = parent.path ? parent.path + '/' + entry.name : entry.name;
      const dir = join(parent.dir, entry.name);
      const common = /^(frontend|client|web)$|^apps\/[^/]+$/.test(path);
      const excluded = globs.some(g => g.startsWith('!') && matchesWorkspace(path, [g.slice(1)]));
      if (!excluded && (common || matchesWorkspace(path, globs)) && readJson(join(dir, 'package.json'), root)) {
        // Never print paths carrying key-shaped folder names.
        if (/^[A-Za-z0-9@/._ -]{1,200}$/.test(path) && screenString(path, 'project hint')) out.push(path);
      }
      if (parent.depth < 5 && (globs.length || path === 'apps')) queue.push({ dir, path, depth: parent.depth + 1 });
    }
  }
  return out.sort();
}

export function selectProject(root, hint) {
  if (!hint) return realpathSync(root);
  const base = realpathSync(root); const target = realpathSync(resolve(root, hint));
  const path = relative(base, target);
  if (isAbsolute(hint) || !path || path === '..' || path.startsWith('..' + sep) || isAbsolute(path)
    || !statSync(target).isDirectory() || !readJson(join(target, 'package.json'), target)) throw new Error('project');
  return target;
}

export function fromPnpmLock(text) {
  const out = []; const section = /^packages:\s*\r?\n([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(text)?.[1] || '';
  const declarations = [];
  const unquote = value => value?.trim().replace(/^['"]|['"]$/g, '');
  const importers = text.slice(0, text.search(/^packages:/m)).split(/\r?\n/);
  // Read importer edges, including v5's separate specifiers map. Scope each map
  // to its importer so one workspace's source declaration cannot hide another.
  const scopes = new Map();
  for (let i = 0; i < importers.length; i++) {
    const heading = /^( *)(specifiers|dependencies|devDependencies|optionalDependencies):\s*$/.exec(importers[i]);
    if (!heading) continue;
    let parent = '';
    for (let j = i - 1; j >= 0; j--) if (importers[j].trim() && /^ */.exec(importers[j])[0].length < heading[1].length) { parent = String(j); break; }
    if (!scopes.has(parent)) scopes.set(parent, { specs: new Map(), edges: [] });
    const scope = scopes.get(parent);
    for (let j = i + 1; j < importers.length; j++) {
      const line = importers[j]; if (!line.trim()) continue;
      const indent = /^ */.exec(line)[0].length;
      if (indent <= heading[1].length) break;
      if (indent !== heading[1].length + 2) continue;
      const entry = /^ *(['"]?)(.+?)\1:\s*(.*)$/.exec(line); if (!entry) continue;
      if (heading[2] === 'specifiers') { scope.specs.set(entry[2], unquote(entry[3])); continue; }
      const edge = { name: entry[2], version: unquote(entry[3]) };
      for (let k = j + 1; !entry[3] && k < importers.length; k++) {
        if (importers[k].trim() && /^ */.exec(importers[k])[0].length <= indent) break;
        const field = /^ *(specifier|version):\s*(.*)$/.exec(importers[k]);
        if (field) edge[field[1] === 'specifier' ? 'spec' : 'version'] = unquote(field[2]);
      }
      scope.edges.push(edge);
    }
  }
  for (const scope of scopes.values()) for (const edge of scope.edges) declarations.push({ ...edge, spec: edge.spec ?? scope.specs.get(edge.name) });
  for (const block of section.split(/(?=^ {2}\S)/m)) {
    const head = block.split(/\r?\n/)[0];
    if (!block.trim()) continue;
    const locator = head.trim().replace(/:$/, '').replace(/^['"]|['"]$/g, '');
    // Old absolute dependency paths prepend the registry to the package path.
    // The package/version delimiter is slash in v5 and @ in v6+.
    const dependencyPath = locator.startsWith('/') || locator.startsWith('@')
      ? locator.replace(/^\//, '') : locator.replace(/^[^/@\s]+\//, '');
    const entry = /^((?:@[^/\s]+\/)?[^@/\s]+)(?:@|\/)(.+)$/.exec(dependencyPath);
    const resolution = /^ {4}resolution:[ \t]*(.*(?:\r?\n {6}[^\r\n]*)*)/m.exec(block)?.[1] || '';
    const field = name => {
      const match = new RegExp('(?:^|[\\s{,])' + name + ':[ \\t]*([^,}\\r\\n]*)').exec(resolution);
      return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : undefined;
    };
    const tarball = field('tarball'); const repo = field('repo'); const directory = field('directory'); const type = field('type');
    const blockField = name => unquote(new RegExp('^ {4}' + name + ':[ \\t]*(.*)$', 'm').exec(block)?.[1]);
    const rawVersion = entry?.[2];
    // Underscores and parentheses belong to pnpm's peer context, never semver.
    // Check provider prefixes before trimming so an apparent suffix cannot hide one.
    const version = rawVersion && (knownTokenLike(rawVersion) || knownTokenLike(screenNormalized(rawVersion))
      ? rawVersion : rawVersion.split(/[(_]/, 1)[0]);
    const urlKey = tarball && ['https://', 'http://'].some(protocol => tarball === protocol + locator.replace(/^@/, ''));
    const sourceLocator = /^(?:github\.com|gitlab\.com|bitbucket\.org)\//i.test(locator) ? 'git:' + locator : entry?.[2] || locator;
    const specs = declarations.filter(d => d.version === locator || d.name === entry?.[1] && d.version === entry?.[2]).map(d => d.spec);
    // Only actual declarations get Git-shorthand recognition. Dependency-path
    // fragments may identify explicit source protocols, but are not declarations.
    const locatorSpecs = sourceReason(sourceLocator) || /^https?:\/\//i.test(sourceLocator) ? [sourceLocator] : [];
    addClassified(out, { name: semver(version) ? entry?.[1] : blockField('name') || entry?.[1],
      version: version && semver(version) ? version : blockField('version') || version || locator, specs: [...locatorSpecs, ...(urlKey ? [tarball] : []),
      ...relevantSpecs(specs),
      ...(type === 'git' ? ['git:' + (repo || '')] : directory ? ['file:' + directory] : [])], resolution: tarball,
      malformed: repo !== undefined || directory !== undefined || type !== undefined || !field('integrity') }, /^ {4}dev: true\s*$/m.test(block) ? { dev: true } : {}, locator);
  }
  return out;
}

export function readPackages(root) {
  let list = []; let source = 'none';
  const npmLock = t => {
    const json = JSON.parse(t);
    if (!json || !['packages', 'dependencies'].some(k => json[k] && typeof json[k] === 'object' && !Array.isArray(json[k]))) throw new Error('Unrecognized npm lock');
    return fromPackageLock(json, { manifest: readJson(join(lockRoot, 'package.json'), lockRoot) || {} });
  };
  const tries = [
    ['package-lock.json', npmLock],
    ['npm-shrinkwrap.json', npmLock],
    ['bun.lock', fromBunLock],
    ['pnpm-lock.yaml', fromPnpmLock],
    // A shared workspace lock can contain runtime users outside this manifest.
    // Without a complete cross-workspace graph its dev-only status is unknown.
    ['yarn.lock', t => fromYarnLock(t, lockRoot === root && !workspaceGlobs(lockRoot).length ? readJson(join(root, 'package.json'), root) || {} : {})],
  ];
  let lockRoot = root;
  let current = root;
  for (let depth = 0; depth <= 6; depth++) {
    const workspace = matchesWorkspace(relative(current, root).split(sep).join('/'), workspaceGlobs(current));
    if (current === root || workspace) {
      lockRoot = current;
      if (workspace || tries.some(([f]) => projectExists(current, f)) || projectExists(current, 'bun.lockb')) break;
    }
    if (projectExists(current, '.git') || dirname(current) === current || depth === 6) break;
    current = dirname(current);
  }
  const manager = (readJson(join(root, 'package.json'), root)?.packageManager || readJson(join(lockRoot, 'package.json'), lockRoot)?.packageManager || '').split('@')[0];
  const preferred = { npm: ['package-lock.json', 'npm-shrinkwrap.json'], pnpm: ['pnpm-lock.yaml'], yarn: ['yarn.lock'], bun: ['bun.lock'] }[manager] || [];
  const candidates = tries.filter(([f]) => projectExists(lockRoot, f)).sort(([a], [b]) => Number(preferred.includes(b)) - Number(preferred.includes(a)) || statSync(projectPath(lockRoot, b)).mtimeMs - statSync(projectPath(lockRoot, a)).mtimeMs);
  for (const [file, parse] of candidates) {
    const t = read(join(lockRoot, file), lockRoot); if (t == null) continue;
    let ok = true;
    try { list = parse(t); } catch { list = []; ok = false; }
    if (list.length) { source = file; break; }
    // Recognized locks remain authoritative when every entry was excluded; falling back
    // to installed packages could reintroduce names from non-registry sources.
    if (ok && (/\.json$|^bun\.lock$/.test(file) || (file === 'pnpm-lock.yaml' && (/^packages:/m.test(t) || /^lockfileVersion:/m.test(t) && /^importers:/m.test(t))) || (file === 'yarn.lock' && /^(?:__metadata:|# yarn lockfile v1|\S.*:\s*$)/m.test(t)))) { source = file; break; }
  }
  // No node_modules fallback. Only safe registry ranges declared in this project's
  // manifest may supplement an absent/unusable lock, never a recognized empty lock.
  const missing = source === 'none' ? { noLockfile: true, ...(projectExists(lockRoot, 'bun.lockb') || projectExists(root, 'bun.lockb') ? { binaryBun: true } : {}) } : {};
  const seen = new Map(); const pkgs = []; const reasons = new Set(list.incompleteReasons || (list.incomplete ? ['malformed'] : []));
  for (const p of list) {
    const k = p.name + '@' + p.version;
    // Registry versions only. git/file/link/http specs can carry tokens or local paths: never sent.
    const safeName = screenString(p.name, 'package name', undefined, true);
    const safeVersion = screenString(p.version, 'package version');
    if (!safeName || !safeVersion) { reasons.add('screened'); continue; }
    if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(p.name) || !SEMVER.test(String(p.version))) { reasons.add('malformed'); continue; }
    if (seen.has(k)) { if (p.dev !== true) delete seen.get(k).dev; continue; }
    const row = { ecosystem: 'npm', name: p.name, version: p.version, ...(p.dev === true ? { dev: true } : {}) };
    seen.set(k, row); pkgs.push(row);

  }
  const selected = source === 'none' ? declaredPackages(root) : pkgs;
  return { packages: selected.slice(0, MAX_PACKAGES), source, ...missing, ...(reasons.size ? { incomplete: true, incompleteReasons: [...reasons] } : {}), ...(selected.length > MAX_PACKAGES ? { total: selected.length, truncated: true } : {}) };
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
  for (const f of ['.env', '.env.local', '.env.production', '.env.production.local']) collect(parseEnv(read(join(root, f), root)), true);
  collect(procEnv);
  let url = URL_VARS.map(k => env[k]).find(value => /^https:\/\/[a-z0-9-]+\.supabase\.(co|in)\/?$/i.test(value || '')) || '';
  let key = KEY_VARS.map(k => env[k]).find(value => publicKeyKind(value)) || '';
  // Scan every allowed client file even when environment config is complete.
  for (const f of ['src/integrations/supabase/client.ts', 'src/integrations/supabase/client.js', 'src/lib/supabase.ts', 'src/lib/supabase.js', 'lib/supabase.ts', 'utils/supabase.ts']) {
    const t = read(join(root, f), root); if (!t || !clientSource(f, t)) continue;
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
  const pj = readJson(join(root, 'package.json'), root) || {};
  const deps = { ...pj.dependencies, ...pj.devDependencies };
  if (deps['lovable-tagger'] || projectExists(root, '.lovable')) return 'Lovable';
  if (projectExists(root, '.replit')) return 'Replit';
  for (const [marker, label] of Object.entries({ '.bolt': 'Bolt', '.emergent': 'Emergent', '.softgen': 'Softgen', '.leap': 'Leap', '.rocket': 'Rocket', '.v0': 'v0' })) if (projectExists(root, marker)) return label;
  if (String(pj.name || '').toLowerCase().replace(/^@[^/]+\//, '') === 'softgen-starter') return 'Softgen';
  for (const dir of [root, join(root, 'frontend')]) for (const file of ['.env', '.env.local', '.env.production']) {
    for (const value of Object.values(parseEnv(read(join(dir, file), root)))) {
      try { const u = new URL(value); if (/^https?:$/.test(u.protocol) && /\.(emergentagent\.com|emergent\.host)$/.test(u.hostname)) return 'Emergent'; } catch {}
    }
  }
  if (deps['@base44/sdk']) return 'Base44';
  if (Object.hasOwn(readJson(join(root, 'metadata.json'), root) || {}, 'requestFramePermissions') || (pj.name === 'react-example' && deps['@google/genai']) || ['ts', 'js', 'mjs', 'mts'].some(ext => /process\.env\.GEMINI_API_KEY/.test(read(join(root, 'vite.config.' + ext), root) || ''))) return 'Google AI Studio';
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
function knownTokenLike(value) {
  return /sb_publishable_|sb_secret_|sk_live_|sk_test_|sk-ant-|sk-proj-|rk_live_|service_role|svk_/i.test(value) || /eyJ/.test(value)
    || /(?:npm_|gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}/i.test(value)
    || /sk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}/i.test(value);
}
export function secretLike(value, packageName = false, credentials = true, packageVersion = false) {
  if (typeof value !== 'string') return false;
  return [value, screenNormalized(value)].some(v => {
    // eyJ is case-sensitive (base64 of '{"'): lowercase "eyj" occurs in ordinary words (honeyjar, journeyjs).
    if (knownTokenLike(v)) return true;
    if (credentials && (/[a-z][a-z0-9+.-]*:\/\/[^\s/?#]*@/i.test(v) || /(?:^|[?&])(?:apikey|api_key|access_token|token|key|sig|signature|secret|password)=/i.test(v))) return true;
    // Within a run, a separator-free piece of >= 32 characters, or >= 16 mixing letters and digits, is key
    // material; hyphenated words and paths ("some-long-path/another-segment") are not. Real npm package
    // names are exempt from this long-run rule only, never from the key prefixes above.
    if (packageName && /^(@[\w.-]+\/)?[\w.-]{1,214}$/.test(value)) return false;
    // Registry semver identifiers commonly contain long commit hashes. Keep the
    // provider-prefix checks above, but do not apply generic entropy screening.
    if (packageVersion && SEMVER.test(value)) return false;
    return (v.match(/[A-Za-z0-9+/_=-]{40,}/g) || []).some(run => run.split(/[-/_+=]/)
      .some(piece => piece.length >= 32 || (piece.length >= 16 && /[a-z]/i.test(piece) && /\d/.test(piece))));
  });
}
// Screening warnings are collected (deduplicated) and printed by the CLI after the summary.
const screenWarnings = new Set();
export function takeScreenWarnings() { const list = [...screenWarnings]; screenWarnings.clear(); return list; }
export function screenString(value, field, warn = message => screenWarnings.add(message), packageName = false) {
  if (typeof value !== 'string') return '';
  if (!secretLike(value, packageName, false, field === 'package version')) return value;
  warn('Dropped ' + field + ': it looked like a key.');
  return '';
}
export function appName(root, explicit = '', url = '') {
  let host = ''; try { host = new URL(url).hostname; if (Object.keys(HOSTS).some(s => host.endsWith('.' + s))) host = host.split('.')[0]; } catch {}
  for (const candidate of [explicit, host, readJson(join(root, 'package.json'), root)?.name]) {
    const raw = String(candidate || '').trim();
    if (!screenString(raw, 'name')) { if (raw) return ''; continue; }
    const n = raw.replace(/[^A-Za-z0-9 @/._-]/g, '').trim();
    if (n && (!screenString(n, 'name') || !screenString(n.slice(0, 80), 'name'))) return '';
    if (n && !TEMPLATES.has(n.toLowerCase().replace(/^@[^/]+\//, '').replace(/_/g, '-'))) return n.slice(0, 80);
  }
  return '';
}
export function packageManager(root, env = process.env) {
  const field = readJson(join(root, 'package.json'), root)?.packageManager?.split('@')[0];
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(field)) return field;
  const source = readPackages(root).source;
  if (source.startsWith('pnpm')) return 'pnpm';
  if (source.startsWith('yarn')) return 'yarn';
  if (source.startsWith('bun') || projectExists(root, 'bun.lockb')) return 'bun';
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
  const { packages, source, truncated, incomplete } = readPackages(root);
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
    ...(incomplete ? { incomplete: true } : {}),
    supabase,
  }).filter(([, value]) => value !== ''));
}
