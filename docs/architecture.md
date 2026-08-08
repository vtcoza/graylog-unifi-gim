# Architecture

```text
Raw/Plaintext UDP
        |
        v
format detection -----> malformed/unsupported stream
   |             |
  CEF        device syslog
   |             |
   +------ vendor parsing
                |
          GIM normalization
                |
        severity/enrichment
                |
          stream routing
                |
      events and dashboards
```

The input carries the static field `unifi_ingest=true`. The pipeline attaches
to Graylog's default stream so input messages cannot miss processing during
their first stream-routing pass; stage 0 immediately stops non-UniFi messages
using that static-field guard. The `UniFi - Raw` stream remains the searchable
raw classification. Stages deliberately separate envelope detection, vendor
parsing, normalization, severity, and routing so a new vendor can later reuse
normalization without sharing its parser.

## Processing contract

1. Detection labels CEF, device syslog, or malformed input and copies the raw
   value to `full_message`.
2. CEF parsing starts at `CEF:` so an RFC3164 prefix is harmless. Device syslog
   parses the emitting hostname, compact MAC, model, firmware, and process.
3. Signature rules classify only message families represented by fixtures.
4. Normalization adds GIM schema fields and `unifi_*` extensions. No source
   field is renamed or removed.
5. Severity keeps the syslog-style name under `unifi_severity` and maps it to
   GIM's five-level `event_severity`/`event_severity_level` pair.
6. Routing keeps messages in the default stream and adds appropriate UniFi
   streams. Unknown messages remain visible.

The Python parser is a regression oracle, not an ingest service. Graylog
pipeline rules are the deployed implementation; release testing replays the
same fixture corpus against Graylog.
