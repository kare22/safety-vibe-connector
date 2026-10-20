# Contributing

Only the connector client code lives here. Use Node 22; there are no dependencies or install scripts.

Run `node --test --experimental-test-isolation=none test/index.js`. Tests use temporary fixtures and local mock HTTP servers on 127.0.0.1, with fabricated keys. No database or dashboard source is needed.

For a release, update package.json and the versioned documentation, run tests, and tag the matching version as `vX.Y.Z`. A pushed tag triggers GitHub Actions, verifies the version, runs tests, then publishes to npm with provenance. The workflow uses the repository NPM_TOKEN secret. Check the source and release changes before pushing a tag.
