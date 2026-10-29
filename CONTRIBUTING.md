# Contributing

Only the connector client code lives here. Use Node 22; there are no dependencies or install scripts.

Run each `test/*.test.mjs` file separately with `node --test --test-concurrency=1 <file>`, sequentially. The CI and publish workflows discover every test file using this glob, including renamed or newly added regressions. Tests use temporary fixtures and local mock HTTP servers on 127.0.0.1, with fabricated keys. No database or dashboard source is needed.

Both GitHub Actions are pinned to full commit SHAs (actions/checkout v4.3.1, actions/setup-node v4.4.0), with the version in a comment. When updating an action, pin the new release to its full commit SHA again.

For a release, update package.json and the versioned documentation, run tests, and tag the matching version as `vX.Y.Z`. A pushed tag triggers GitHub Actions, verifies the version, runs tests, then publishes to npm with provenance. The workflow uses the repository NPM_TOKEN secret. Check the source and release changes before pushing a tag.
