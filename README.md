# safetyvibe-connect

SafetyVibe Connect reads package.json, the lockfile, and client-exposed Supabase config (client-prefixed env vars and the client Supabase file). It reports your package list so we can warn you about vulnerable dependencies. The JSON body sends exactly: v, optional name, url, platform and environment, lockfile, versions_source, source, packages, optional truncated, and supabase (null, or project_ref and host with key_kind and key_fingerprint, or secret_key_exposed_client_side). It never sends Supabase keys, secrets or file contents. Requires Node >=18; no dependencies or package install scripts.

Full source: https://safetyvibe.eu/connect/source/0.3.2

## 0.3.2: review an inventory locally

For a manual no-install inventory, ask: "Show me a safe inventory summary and JSON from package.json and a supported lockfile; I will review it locally." Request no installation, execution, file changes, keys or environment values. Unknown facts stay unknown. Review the output locally; dashboard paste acceptance and save/refresh compatibility require separate verification, including exposed-secret flags and declaration whitespace.

With Node and a terminal, run without adding the connector to your project (npx fetches and executes the package):

```sh
npx -y safetyvibe-connect@0.3.2 inventory --json --compact
npx -y safetyvibe-connect@0.3.2 inventory --project frontend --json --compact
npx -y safetyvibe-connect@0.3.2 setup --dry-run --json
```

`inventory` always makes no network call and writes nothing unless you pass `--out`. It does not install the connector, add hooks or update link settings. Warnings and guidance stay on stderr when stdout contains JSON. Compact JSON is one line and retains every inventory row (up to the existing 5000-row cap). This prepares a reviewable inventory; it does not establish dashboard acceptance.

Common subprojects (frontend, client, web, apps/*) and declared npm/pnpm workspace members are suggested. Discovery is bounded to six levels and 500 entries, skips symlink directories, and never merges projects or changes the selected/linked app. Use `--project DIR` to explicitly select one existing package.json directory inside the current root, or change directories yourself. Exports/config writes apply to that selected directory.

Flag precedence is independent of order: `--summary` or `--json=summary` wins over JSON stdout; `--out` still exports the full body and suppresses JSON stdout; `--json` opts into full JSON. `--compact` only changes JSON formatting and does not enable JSON by itself. An explicit summary plus --out prints a summary and exports the body. Other --out modes keep stdout empty. Real --json reports print the safe request body on stdout and connection/guidance text on stderr.

Counts are local summary metadata, not new JSON fields. Direct means safe registry declarations in the selected package.json. Total means unique name+resolved-version rows in the selected lockfile before truncation; declared means manifest rows when no usable lock exists. The summary separately shows direct dev declarations and confirmed dev-only inventory rows. Yarn v1 resolves direct dev selectors and suppresses the flag for runtime-reachable shared entries; unclassified transitive packages are not labelled dev-only. Shared workspace Yarn locks retain unknown dev-only status because other apps may use those packages at runtime. A shared workspace lock may cover more than the selected app, so its total is explicitly a lockfile total.

When no usable lock exists, safe package.json ranges are preserved verbatim with `versions_source:"declared"` and `lockfile:"none"`. No resolved versions or successful vulnerability checks are invented. Recognized empty or fully excluded locks remain authoritative. Declared bodies (including empty declared inventories) are kept local until dashboard range handling and save/refresh behavior are verified. Real `setup` refuses them with exit 1 before any network call, config migration, link-setting write or hook change; real `scan` emits the same warning and exits 0 for install hooks. This guard also applies with `--json`: a refused real run prints no JSON on stdout. `inventory` and `setup --dry-run` still preview them. An explicit `--out` export is processed before the guard and can write the requested local JSON even when the real report is refused (invalid output paths exit 2). Supply a supported lockfile to send a resolved inventory.

## 0.3.2: connect without adding a dependency

Get a claim token from the dashboard, then run:

```sh
npx -y safetyvibe-connect@0.3.2 setup --no-hook --claim-token <TOKEN>
# pnpm
pnpm dlx safetyvibe-connect@0.3.2 setup --no-hook --claim-token <TOKEN>
# bun
bunx safetyvibe-connect@0.3.2 setup --no-hook --claim-token <TOKEN>
# yarn
yarn dlx safetyvibe-connect@0.3.2 setup --no-hook --claim-token <TOKEN>
```

Add `--url <published URL>` if known. Without a token, setup prints a claim link.
On Replit/pnpm projects, `npm install` can fail with "Cannot read properties of null (reading 'isDescendantOf')".
Use `pnpm add -D safetyvibe-connect@0.3.2`, or run without installing:
`npx -y safetyvibe-connect@0.3.2 setup --no-hook --claim-token <TOKEN>`.
Optional installation commands: `npm install -D safetyvibe-connect@0.3.2`, `pnpm add -D safetyvibe-connect@0.3.2`, `bun add -d safetyvibe-connect@0.3.2`, `yarn add -D safetyvibe-connect@0.3.2`.

## For AI agents

`setup --dry-run` makes no network call and writes nothing unless you pass `--out`. Check cli.mjs line 188: `return 0;` inside `if (flags['dry-run'])`. This exits before the only `fetch(` call. This describes the connector itself; fetching the package with npx is separate.

It reads package.json and one supported lockfile (package-lock.json, npm-shrinkwrap.json, bun.lock, pnpm-lock.yaml or yarn.lock). It may inspect candidate locks and ancestor package.json / pnpm-workspace.yaml files to select a workspace lock, stopping at .git or six parent levels. It checks whether bun.lockb exists, but does not parse it. It reads .safetyviberc.json and .safetyviberc.local.json for local link settings.

It reads and parses .env, .env.local, .env.production and .env.production.local locally, not just their key names. Service-role variable names produce local warnings. Client-prefixed values are checked for secret shapes; SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY and SUPABASE_ANON_KEY with VITE_, NEXT_PUBLIC_, EXPO_PUBLIC_, PUBLIC_, REACT_APP_ or NUXT_PUBLIC_ prefixes supply the URL and public key used locally for a fingerprint. Process env is inspected the same way. Server-only Supabase values are not selected as connection details. For platform detection it also examines URL values in .env, .env.local and .env.production in the root and frontend/; those values are not sent.

Client files scanned for the Supabase URL and key shape, exactly:

- src/integrations/supabase/client.ts
- src/integrations/supabase/client.js
- src/lib/supabase.ts
- src/lib/supabase.js
- lib/supabase.ts
- utils/supabase.ts

Files marked server-only or use server are excluded. Bare prefixes and incomplete JWTs are ignored for secret detection. Full identifiable secrets are flagged even when embedded in larger values, comparisons, validation calls or comments in client files. Source scanning uses a forward token pass with bounded JWT candidates. Only a full sb_secret_ shape (at least 20 body characters), a three-segment service_role JWT, or a JWT with any role other than anon under a publishable/anon key name sets the exposure flag. Unknown keys are never accepted as public.

Platform detection also reads metadata.json and vite.config.ts/js/mjs/mts, package names/dependencies, and checks .lovable, .replit, .bolt, .emergent, .softgen, .leap, .rocket and .v0 markers. The CLI uses cwd / INIT_CWD, package manager and agent/CI environment hints, including BASE44_* and CURSOR_*, plus SAFETYVIBE_API, SAFETYVIBE_URL, SAFETYVIBE_ENV, NODE_ENV, SAFETYVIBE_KEY, SAFETYVIBE_CLAIM_TOKEN and SAFETYVIBE_TIMEOUT_MS. No source files or raw Supabase keys are sent. The complete JSON field list and authentication headers are documented below under "Exactly what is sent".

Source: https://safetyvibe.eu/connect/source/0.3.2

## Exactly what is sent

Preview the report before sending it:

```sh
npx -y safetyvibe-connect@0.3.2 setup --dry-run --json --url https://notes.example.com
```

By default non-TTY and agent/CI runs print five summary lines on stdout plus one Next guidance line: Platform, Lockfile (direct / total or declared counts, direct dev and confirmed dev-only counts), Supabase (fingerprint or exposed-secret flag only), Keys sent: 0, and Dry run: nothing sent. Warnings go to stderr. Use --json for the full body on stdout, with summary, guidance, explanation and destination/header names (values hidden) on stderr. A regular TTY keeps that JSON behaviour by default. --summary or --json=summary wins over --json. Dry-run makes no requests. --out preserves the export behaviour described below.

Real runs print the summary on stdout, ending with Connected: and the dashboard or validated claim link (printed once), followed by one Next guidance line for manual reporting or hook status. Explicit --json puts the safe body on stdout and all summary/guidance on stderr. --quiet suppresses success chatter, but safety warnings always appear on stderr, including during dry runs. Accepted reports show the Connected line even if saving local config or installing the hook fails; warnings and errors follow the summary. Rejected or unreachable reports have no Connected line.

--summary (also --json=summary) prints only the summary plus one guidance line on stdout in dry and real runs, with warnings on stderr and no JSON. --out <file.json> (also --out=file.json) writes the exact JSON body plus newline instead of printing JSON; in dry runs stdout stays empty and the summary stays on stderr unless --summary is also used. It works for real runs too. The file must be new, end in .json, and resolve inside the project root with an existing parent directory; parent symlink escapes are refused. It uses exclusive creation and never overwrites files. Connector config filenames and package.json are reserved so later setup writes cannot replace the exported body. Invalid output paths exit 2, including scan, with an error on stderr.
Example (optional `truncated` appears only when the inventory exceeds 5000):

```json
{
  "v": 1,
  "name": "notes.example.com",
  "url": "https://notes.example.com",
  "environment": "production",
  "lockfile": "package-lock.json",
  "versions_source": "lockfile",
  "source": "connector",
  "packages": [{ "ecosystem": "npm", "name": "vite", "version": "6.0.0", "dev": true }],
  "supabase": { "project_ref": "abcdefghijklmnopqrst", "host": "abcdefghijklmnopqrst.supabase.co", "key_kind": "anon", "key_fingerprint": "12ab34cd" }
}
```

- `v`: report format version.
- `name`: explicit or rc name, then URL host (first label for platform hosts), then package name, skipping template and key-like names; limited to 80 letters, digits, spaces, @ / . _ -; omitted when unknown.
- `url`: HTTP(S) origin and path only, without credentials, query or fragment; paths are kept only with up to eight safe ASCII segments of at most 40 characters, excluding sb_, svk_ and eyJ markers; key-like hostnames are rejected; omitted when unknown.
- `platform`: detected project builder/hosting label; omitted when unknown.
- `environment`: `SAFETYVIBE_ENV`, or production when `NODE_ENV=production`; limited to 20 letters, digits, underscores or hyphens; omitted when unknown.
- `lockfile`: selected lockfile filename, or `none` when no readable lockfile exists. Parent locks are used only at workspace roots when the project matches a workspace glob in package.json workspaces (array or workspaces.packages) or the pnpm-workspace.yaml packages list. Literal paths, * and ** are supported; negated globs exclude matching paths from membership. Search stops at .git or six parent levels.
- `packages`: registry package names and versions, npm ecosystem, and optional `dev: true` for dev-only dependencies when recorded in the lockfile. Workspace entries are excluded; incompatible optional npm binaries are excluded. Names that a lockfile declares with a git/tarball/file/link spec are excluded, including hoisted entries. Recognized empty or fully excluded locks remain authoritative. Supported formats are npm v1/v2/v3, Yarn v1/Berry, pnpm v5.4/v6/v9 and text bun.lock; installed node_modules folders are never read. Without a readable lockfile (none, only binary bun.lockb, or an unparseable one), safe package.json registry ranges are used locally with `lockfile` set to `none` and `versions_source` set to `declared`. The CLI prints: "No readable lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock); using safe package.json declarations, not resolved versions." Network reports of declared inventories are blocked pending separately verified receiver support. For bun.lockb run `bun install --save-text-lockfile` to create bun.lock.
- `truncated`: optional boolean; only the first 5000 packages are sent.
- `versions_source`: `lockfile` for resolved inventory; `declared` for safe manifest ranges in local inventory/dry-run output.
- `source`: always `connector`.
- `supabase`: null unless a validated URL and public key are found, or a client-exposed secret is detected. Public keys yield only `project_ref`, `host`, `key_kind` (`anon` or `publishable`) and `key_fingerprint` (first eight lowercase hex characters of SHA-256 of the UTF-8 key). `host` is the URL host only; `project_ref` is the lowercase 20-character alphanumeric ref of a .supabase.co host, otherwise null. An exposed secret always wins: only `{ "project_ref": null, "host": null, "secret_key_exposed_client_side": true }` is sent, with project_ref/host filled when a validated URL is known. No key kind, fingerprint or length is sent for secrets.

Nested fields: `packages[].ecosystem` is `npm`; `packages[].name` is the registry name; `packages[].version` is the exact lockfile version, or the unchanged safe declared registry range when versions_source is declared; optional `packages[].dev` is true for dev-only packages. `supabase.project_ref` identifies the project (or null); `supabase.host` is the validated host (or null); `supabase.key_kind` is anon or publishable; `supabase.key_fingerprint` is the eight-character SHA-256 prefix; `supabase.secret_key_exposed_client_side` is true only for a detected client-exposed secret and replaces kind/fingerprint.

All report strings are screened before sending or printing: key-like values (including encoded and Unicode-disguised keys) are dropped, with a local warning naming only the field. A key-like URL is dropped entirely.

Never sent: source code, file paths, full lockfiles, .env files, Supabase keys (including anon/publishable), secrets, URL credentials or query strings.
The request headers x-safetyvibe-site, x-safetyvibe-key and x-safetyvibe-claim-token carry the validated UUID site ID, validated report key and validated one-shot claim token when available; these are not in the JSON body. The server validates public keys too for older clients; this connector sends no Supabase keys.
Public keys are read only from client-exposed variables (prefixes VITE_, NEXT_PUBLIC_, EXPO_PUBLIC_, PUBLIC_, REACT_APP_, NUXT_PUBLIC_; from the environment or .env files) or a client-side Supabase source file (src/integrations/supabase/client.*, src/lib/supabase.*, lib/supabase.ts, utils/supabase.ts). Files that contain the quoted text server-only or use server anywhere (even in a comment), are named *.server.*, or sit under server/, api/, app/api/, pages/api/, functions/, supabase/functions/, netlify/functions/ or are middleware.* are skipped. Server-only names such as SUPABASE_URL or SUPABASE_ANON_KEY are not selected as connection details. Every client-prefixed variable in process env and .env/.env.local/.env.production/.env.production.local is checked for exposed secrets, as are full secret-shaped runs in the scanned client files, independent of quote pairing (a stray apostrophe in a comment cannot hide a full secret), including full-secret comparisons and validation calls, while ignoring bare prefixes. Full secret shapes embedded in larger client values also set the flag. A key split across concatenated strings is not detected. Any service-role variable name in a .env* file, including SUPABASE_SERVICE_ROLE_KEY and SUPABASE_SERVICE_KEY, produces a separate local warning; its presence alone never sets an exposure flag or adds anything to the body. Local warnings name only the variable or relative client file, never the value, and tell you to rotate exposed secrets in Supabase.

Review the entire implementation in `cli.mjs` and `lib.mjs`. There are no dependencies and no install scripts in this package itself.
By default reports go only to `https://dashboard.safetyvibe.eu/connect/api/v1/report`. The committed rc cannot change the destination.
An explicit `SAFETYVIBE_API` environment override supports HTTPS, or HTTP on localhost/127.0.0.1/[::1] for local testing. Redirects are refused.

## Changes

0.3.2 (2026-10-19) adds the local `inventory` command, `--project` selection and bounded hints for common subprojects and npm/pnpm workspaces. Summaries distinguish direct declarations from total lockfile rows and show direct dev and confirmed dev-only counts; Yarn v1 resolves direct dev selectors without labelling runtime-shared or unknown transitive rows dev-only. `--json --compact` emits one-line full JSON; `--json=summary` selects the summary with explicit flag precedence. Without a usable lockfile, safe manifest ranges are preserved as `versions_source:"declared"` for local review; real declared reports remain blocked pending dashboard verification. Client-source secret scanning now uses a bounded forward pass and detects full secrets embedded in larger values, comparisons, validation calls and comments while ignoring bare prefixes. BASE44_* and CURSOR_* agent hints select summary output, which includes a Next guidance line.

0.3.1 fixes false secret alarms from Supabase prefix checks while keeping real secret warnings and public fingerprints. Non-TTY and agent/CI runs default to a five-line summary; --json opts into the body. It checks config writability before sending, stops re-sending env claim tokens for linked projects, warns locally about service-role variable names, and exits 2 for bad --out paths even on scan. It adds AI-agent source guidance.

0.3.0 never sends Supabase keys: it reports public-key fingerprints or exposed-secret flags, puts a five-line summary first, adds --summary and safe --out JSON export, and ships MIT licensing and security contact details. 0.2.2 improves response deadlines, registry-only inventory, project selection and app labels, restores flag-only setup, and rejects ambiguous JWT payloads. It reads pnpm v5.4 locks and no longer reads installed node_modules folders: without a readable lockfile no packages are sent. 0.2.1 fixed a bug where a key on a commented .env line could be included; upgrade from 0.2.0.

[Documentation](https://safetyvibe.eu/connect) and [changelog / what is sent](https://safetyvibe.eu/connect/changelog).

## Files written and removal

Before a setup/scan request, the connector probes directory writability and checks existing config files; a failure sends nothing and exits 1 for setup (0 for scan). Then legacy credentials are migrated best-effort into the local file, the committed api field is dropped and its URL normalized. Dry-run writes only an explicitly requested --out file; status and help never write. After a successful report:

- `.safetyviberc.json`: app ID, normalized public URL, optional name and `hook: false`.
- `.safetyviberc.local.json`: report key and optional fallback claim token; never commit this file. The token is removed once used or rejected as expired/used. Once a valid site ID and report key are present, SAFETYVIBE_CLAIM_TOKEN is not re-sent. Only stored credentials require the local file and ignore entry. The ignore entry is attempted first, then this file is written with mode 0600. An ignore failure warns and fails setup; scan still exits 0. Empty local credentials are removed.
- `.gitignore`: adds the local config filename.
- `package.json`: setup normally adds a postinstall report hook. `--no-hook` leaves package.json untouched and persists this preference. Existing unsafe shell scripts are left untouched with a manual instruction.

The project directory is cwd. INIT_CWD is used only when its own package.json lists the connector or its postinstall hook and it is not a workspace root. Scan at an npm/Yarn workspace root (package.json workspaces) or pnpm workspace root (pnpm-workspace.yaml with a packages list) that has no app ID in .safetyviberc.json is skipped without network or writes; run setup in the app directory. A root that was linked by running setup there is treated like any app: it reports and updates its rc files. Dry-run still previews the selected directory. An unlinked scan without a key or claim token skips projects without the connector dependency. Requests have one deadline of at most 10 seconds, including the response body, capped at 64 KiB. Failed responses keep the token unless the server reports it expired or already used, and do not install a hook.

The postinstall hook runs `safetyvibe-connect scan --quiet || exit 0`: it re-sends the current inventory and public Supabase details using the local report key, suppresses success chatter but keeps safety warnings on stderr, and never fails installation. Without a local key it skips reporting for a linked app unless SAFETYVIBE_KEY or a claim token is supplied.

Without terminal access, first add `.safetyviberc.local.json` to `.gitignore`, then write `{"claimToken": "<TOKEN>"}` into `.safetyviberc.local.json` and configure the dependency and postinstall hook. Never put the token in the committed `.safetyviberc.json`.

For manual reporting use `npx -y safetyvibe-connect@0.3.2 scan` (pnpm: `pnpm dlx`, bun: `bunx`, yarn: `yarn dlx`).
Remove the connector dependency if installed, its postinstall command, both rc files, and the local-config .gitignore entry. Keep other postinstall commands.

## Commands

| Command | Effect |
|---|---|
| `setup [--claim-token T] [--url URL] [--name NAME] [--no-hook]` | Send report, save config, optionally add hook |
| `setup --dry-run` or `--dry-run` | Preview summary (--json for the body) without network; only --out writes a file |
| `inventory [--project DIR] [--json] [--compact]` | Local review body/summary; no network or config writes, only explicit --out writes |
| `scan [--quiet]` | Re-report; exits 0 for install hooks, except bad --out exits 2 |
| `status` | Show local link state |
| `help`, `--help`, `-h`, no arguments | Usage only |
| `--version`, `-v` | Package version only |

Flags without a command imply setup. Unknown name, URL, platform and environment fields are omitted, never empty strings.

Value flags accept `--flag=value` or `--flag value`, including values starting with a dash. In the space form, a known flag (also with `=...`) is treated as a missing value. Unknown commands/flags and missing values exit 2, except scan exits 0 (a missing --out value still exits 2).
