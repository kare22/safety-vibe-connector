import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

export function project(t, manifest = {}) {
  const root = mkdtempSync(join(tmpdir(), 'sv-connector-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, 'package.json'), JSON.stringify(manifest));
  return root;
}
export function json(root, file, value) { writeFileSync(join(root, file), JSON.stringify(value)); }
export function run(root, args, extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/SUPABASE|^SAFETYVIBE_|^INIT_CWD$|^NODE_OPTIONS$/.test(k)) delete env[k];
  Object.assign(env, { INIT_CWD: root, SAFETYVIBE_API: 'http://127.0.0.1:9' }, extra);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../cli.mjs', import.meta.url)), ...args], { cwd: root, env });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}
export async function receiver(t) {
  const hits = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      hits.push(JSON.parse(raw));
      res.end(JSON.stringify({ site: '12345678-1234-1234-1234-123456789abc', key: 'svk_' + 'a'.repeat(32), claimed: true }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { hits, SAFETYVIBE_API: 'http://127.0.0.1:' + server.address().port + '/connect/api/v1' };
}
