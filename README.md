# Graylog UniFi GIM

Open-source UniFi OS integration for Graylog Open. It accepts mixed modern
UniFi Network CEF and device syslog on a Raw/Plaintext UDP input, preserves the
vendor payload, and adds fields compatible with the Graylog Information Model
(GIM).

> **Release status:** `0.1.0` is an evidence-gated preview for Graylog Open
> 7.1.5 and UniFi Network 10.4.x. Only fixture-backed message families are
> classified. Unknown messages remain searchable and are routed to the parser
> health stream.

## Included

- Mixed CEF/syslog format detection and staged pipeline processing.
- Official underscore-style GIM fields alongside original `UNIFI*` fields.
- UniFi extension fields under `unifi_*`.
- Streams, CSV lookup tables, disabled event definitions, and four dashboards.
- Sanitized golden fixtures and an executable Python regression oracle.
- Two deterministic content packs:
  - `graylog-unifi-gim-0.1.0-with-input.json`
  - `graylog-unifi-gim-0.1.0-assets-only.json`

## Quick start

1. Read [installation.md](docs/installation.md) and choose exactly one pack.
2. Mount `lookups/` read-only at `/usr/share/graylog/data/unifi-gim/` on every
   Graylog node.
3. For the self-contained pack, select the UDP bind address and port during
   installation. The default is `0.0.0.0:1515`.
4. For the assets-only pack, add the static field `unifi_ingest=true` to an
   existing Raw/Plaintext UDP input.
5. Configure the recommended [field types](docs/field-types.md), rotate the
   target write index, then send UniFi logs.

The event definitions install disabled and no notification is created.

## Supported in 0.1

| Family | Format | Normalized value |
|---|---|---|
| Wired client connected/disconnected | CEF 403/404 | `network.client.*` |
| Wi-Fi station associated/disassociated | Device syslog | `network.client.*` |
| Switch port link up/down | Device syslog | `network.port.*` |
| Switch STP blocking/forwarding | Device syslog | `network.port.*` |
| Mesh halt timeout | Device syslog | `wireless.mesh.timeout` |
| Device reboot command | Device syslog | `device.reboot` |

Upgrade, gateway failover/failback, and gateway-specific parsing remain
coverage gaps until representative raw fixtures are contributed. See the full
[coverage matrix](docs/coverage.md).

## Development

```text
python -m pip install -e ".[test]"
python -m pytest
unifi-gim build
```

Every recognized parser signature requires a sanitized raw fixture and an
expected JSON contract. See [fixture contribution](docs/fixtures.md).

## Design guarantees

- `message` and `full_message` preserve the complete raw message.
- Original CEF extension fields, including every `UNIFI*` key, are retained.
- Unsupported and malformed records are labeled; they are never dropped.
- `gim_*` values come from the official GIM vocabulary only.
- Public fixtures contain no production hostnames, addresses, MACs, sites, or
  client aliases. The local `input/` corpus is ignored by Git.

Architecture and field semantics are documented in
[architecture.md](docs/architecture.md) and [fields.md](docs/fields.md).

## License

GPL-3.0-only. This project is independent community software and is not
affiliated with or endorsed by Graylog, Inc. or Ubiquiti Inc.

