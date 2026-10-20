# Security

Report vulnerabilities privately to safetyvibe@advertis.ee.
See https://safetyvibe.eu/.well-known/security.txt.

The package reads package.json, lockfiles and client-exposed Supabase config,
and sends app metadata, registry package versions and Supabase project identity
with a public-key fingerprint or an exposed-secret flag, never Supabase keys,
secrets or file contents.
