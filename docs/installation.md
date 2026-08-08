# Installation

## Prerequisites

- Graylog Open 7.1.x with the Pipeline Processor enabled after Message Filter
  Chain.
- Administrator access.
- A Raw/Plaintext UDP path from UniFi.
- Read access for Graylog UID 1100 to the lookup CSV mount.

## Mount lookup data

Mount this repository's `lookups/` directory on every Graylog node:

```yaml
services:
  graylog:
    volumes:
      - ./lookups:/usr/share/graylog/data/unifi-gim:ro
```

The installed adapters use that exact path. Verify all lookup tables report a
healthy adapter before enabling ingestion.

## Choose one pack

### Self-contained

Upload `content-pack/graylog-unifi-gim-0.1.0-with-input.json`. During install,
choose the bind address and UDP port (default `0.0.0.0:1515`). The global
Raw/Plaintext UDP input includes `unifi_ingest=true`.

### Assets-only

Upload `content-pack/graylog-unifi-gim-0.1.0-assets-only.json`. On the existing
Raw/Plaintext UDP input add this static field:

```text
unifi_ingest = true
```

Do not install both variants. They intentionally share dependent entity IDs.

## Complete setup

1. Install the recommended field-type profile before the first message.
2. Rotate the target write index after applying the profile.
3. Confirm `UniFi - Raw` is receiving messages and the `UniFi GIM` pipeline is
   connected to it.
4. Check `UniFi - Parser Health`; unsupported messages are expected until a
   signature is supported.
5. Review and tune event thresholds before enabling individual definitions.

UniFi should send both CEF and device syslog to the same destination. Do not
use a CEF-only or syslog-only Graylog input for this mixed exporter.

