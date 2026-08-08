# Contributing

Parser changes start with evidence. Do not submit parsed Graylog exports as
fixtures; submit one raw message per parser signature and firmware behavior.

1. Sanitize hostnames, sites, aliases, IPs, and MACs as described in
   [docs/fixtures.md](docs/fixtures.md).
2. Add `samples/raw/<id>.log`, `samples/expected/<id>.json`, and one manifest
   entry under `tests/fixtures/manifest.json`.
3. Update pipeline rules and the Python reference parser together.
4. Run `python -m pytest` and `unifi-gim build`.
5. Document new mappings and firmware coverage.

Never remove a vendor field to make a test pass. New `gim_*` classifications
must use Graylog's published vocabulary and satisfy its required-field rules.

