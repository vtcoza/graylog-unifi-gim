# Coverage matrix

| Message family | Evidence | Status |
|---|---|---|
| CEF wired client connected (403) | UniFi Network 10.4.57 | Supported |
| CEF wired client disconnected (404) | UniFi Network 10.4.57 | Supported |
| Wi-Fi association/disassociation | U6 6.7.54, UAP-AC-LR 6.8.2 | Supported |
| Port link/STP state | US/USW 7.4.1 | Supported |
| Mesh halt timeout | U6 6.7.54 | Supported |
| Reboot command | U6 and USW samples | Supported |
| Generic device envelope/process | AP and switch samples | Partial; routed unsupported |
| Upgrade | No current fixture | Not classified |
| Gateway failover/failback | No gateway fixture | Not classified |
| Gateway-specific syslog | No gateway fixture | Not classified |
| Other CEF IDs | Insufficient samples | Preserved; routed unsupported |

The source corpus contained 131,709 rows, but public regression coverage is by
parser signature rather than by every repeated kernel/debug line. A signature
requires extra fixtures whenever firmware changes its structure.

