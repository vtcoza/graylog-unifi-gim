# Fixture contribution

Public fixtures must be raw wire messages, not parsed Graylog JSON. Keep the
RFC3164/CEF/device envelope exactly as emitted and change only identifiers.

Use fictional hostnames and site/client labels, RFC 5737 addresses
(`192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`), and locally
administered unicast MACs beginning with `02`.

For each parser signature:

1. Add one line to `samples/raw/<id>.log`.
2. Add stable contract fields to `samples/expected/<id>.json`.
3. Add format, firmware, and expected status to the fixture manifest.
4. Update both the Graylog rule and Python reference parser.
5. Run tests and rebuild both packs.

Include malformed examples, duplicates, CEF escaping, missing optional fields,
and firmware variants where available. Never commit the local `input/` export.

