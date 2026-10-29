# Security

Report vulnerabilities privately to safetyvibe@advertis.ee.
See https://safetyvibe.eu/.well-known/security.txt.

The package reads package.json, lockfiles and client-exposed Supabase config,
and sends app metadata, registry package versions and Supabase project identity
with a public-key fingerprint or an exposed-secret flag. Raw Supabase keys and
file contents are excluded from the report body. Known key/token shapes are
screened in metadata; arbitrary secrets can evade screening. Review local JSON
with inventory or --dry-run before reporting. Report/claim credentials travel
separately in authentication headers.
