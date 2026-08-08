# Field reference

Graylog GIM uses underscore-separated fields. Dotted names from ECS are not
created.

| UniFi source | Normalized field | Meaning |
|---|---|---|
| `UNIFIclientIp` | `source_ip` | Client address |
| `UNIFIclientMac` | `source_mac` | Client MAC |
| `UNIFIclientHostname` / alias | `source_hostname` | Client identity |
| `UNIFI*ConnectedToDeviceName` | `destination_hostname` | Attachment device |
| `UNIFI*ConnectedToDeviceIp` | `destination_ip` | Attachment-device address |
| `UNIFI*ConnectedToDeviceMac` | `destination_mac` | Attachment-device MAC |
| CEF signature | `event_code`, `event_id` | Vendor event identifier |
| `UNIFIhost` | `event_observer_hostname`, `event_reporter` | Controller/reporter |
| `UNIFInetworkName` | `network_name` | Network name |
| `UNIFInetworkSubnet` | `network_cidr` | Network prefix |
| `UNIFInetworkVlan` | `network_vlan` | VLAN number |
| device header | `host_*`, `event_source` | Emitting AP/switch/gateway |
| process prefix | `process_name`, `process_pid` | Emitting process |

Precise operational taxonomy is stored in `unifi_event_type`. Official
`gim_*` category values are added only when the event meets the GIM required
field contract. Client attachment events currently use the official generic
network code `129999` while retaining the precise UniFi value.

## Severity

| `unifi_severity` | `event_severity` | Level |
|---|---|---:|
| debug, info | informational | 1 |
| notice | low | 2 |
| warning | medium | 3 |
| error | high | 4 |
| critical | critical | 5 |

CEF's original numeric severity remains in `vendor_event_severity_level`.

