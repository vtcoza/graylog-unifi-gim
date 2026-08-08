# Marketplace release checklist

- Version, pack revision, changelog, and filenames agree.
- Both packs build deterministically and have distinct pack IDs.
- Only one variant is installed in each clean Graylog test instance.
- Lookup files are mounted and all adapters are healthy.
- All fixtures replay without processing or indexing failures.
- Streams, dashboard references, and disabled event definitions are present.
- No private corpus or production identifier is tracked.
- GPL-3.0-only metadata and repository URL are present.
- Release notes list evidence-backed coverage and known gaps.

Do not call a build Marketplace-ready until the Docker release gate imports and
replays both variants against the target Graylog version.

