"""Deterministic reference parser for golden-fixture regression tests.

Graylog pipeline rules are the production runtime. This parser models their
observable field contract so changes can be reviewed without a live cluster.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


RFC3164_RE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<relay>\S+)\s+(?P<payload>.*)$"
)
DEVICE_RE = re.compile(
    r"^(?P<host>\S+)\s+(?P<mac>[0-9A-Fa-f]{12}),(?P<model>.+)-"
    r"(?P<version>\d+\.\d+\.\d+\+\d+):\s*(?P<body>.*)$"
)
PROCESS_RE = re.compile(
    r"^(?P<process>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<body>.*)$"
)
PORT_LINK_RE = re.compile(
    r"(?:\[\s*[\d.]+\]\s*)?Port\s+(?P<port>\d+)\s+link\s+(?P<state>up|down)$", re.I
)
PORT_STP_RE = re.compile(
    r"(?:\[\s*[\d.]+\]\s*)?Port\s+(?P<port>\d+)\s+moving\s+from\s+"
    r"(?P<from>[A-Za-z]+)\s+to\s+(?P<to>[A-Za-z]+)$",
    re.I,
)
WLAN_RE = re.compile(
    r"^(?P<interface>[^:]+):\s+STA\s+(?P<client>[0-9A-Fa-f:]{17})\s+"
    r"IEEE\s+802\.11:\s+(?P<state>associated|disassociated)$",
    re.I,
)

CEF_EVENTS = {
    "403": ("connected", "network.client.connected"),
    "404": ("disconnected", "network.client.disconnected"),
}
SYSLOG_SEVERITY = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}
GIM_SEVERITY = {
    "debug": ("informational", 1),
    "info": ("informational", 1),
    "notice": ("low", 2),
    "warning": ("medium", 3),
    "error": ("high", 4),
    "critical": ("critical", 5),
}


def _mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
    if len(compact) != 12:
        return value.lower()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _bytes(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)\s*", value, re.I)
    if not match:
        return None
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    return round(float(match.group(1)) * units[match.group(2).upper()])


def _duration(value: str | None) -> int | None:
    if not value:
        return None
    total = 0
    found = False
    for number, unit in re.findall(r"(\d+)\s*([dhms])", value, re.I):
        found = True
        total += int(number) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit.lower()]
    return total if found else None


def _set(out: dict[str, Any], name: str, value: Any) -> None:
    if value is not None and value != "":
        out[name] = value


def _apply_severity(out: dict[str, Any], severity: str) -> None:
    out["unifi_severity"] = severity
    out["vendor_event_severity"] = severity
    out["event_severity"], out["event_severity_level"] = GIM_SEVERITY[severity]


def _cef_split(value: str, limit: int = 7) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append("\\" + char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|" and len(parts) < limit:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def _cef_unescape(value: str) -> str:
    return re.sub(r"\\([\\|=])", r"\1", value).replace("\\n", "\n").replace("\\r", "\r")


def _cef_extensions(value: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*)=", value))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        result[match.group(1)] = _cef_unescape(value[start:end].strip())
    return result


def _common_network_gim(out: dict[str, Any]) -> None:
    if (out.get("source_ip") or out.get("source_mac")) and (
        out.get("destination_ip") or out.get("destination_mac") or out.get("destination_hostname")
    ):
        out["source_reference"] = out.get("source_ip") or out.get("source_mac")
        out["destination_reference"] = (
            out.get("destination_ip") or out.get("destination_mac") or out.get("destination_hostname")
        )
        out["gim_event_type_code"] = 129999
        out["gim_event_category"] = "network"
        out["gim_event_subcategory"] = "network.default"
        out["gim_event_type"] = "network message"


def _parse_cef(payload: str, out: dict[str, Any]) -> dict[str, Any]:
    parts = _cef_split(payload[4:])
    if len(parts) != 8:
        out["unifi_parse_error"] = "invalid_cef_header"
        return out

    cef_version, vendor, product, product_version, signature, name, severity_value, extension = parts
    fields = _cef_extensions(extension)
    out.update(fields)  # Preserve source UNIFI* fields verbatim.
    out.update(
        {
            "unifi_log_format": "cef",
            "unifi_parse_status": "parsed" if signature in CEF_EVENTS else "unsupported",
            "vendor_name": _cef_unescape(vendor),
            "vendor_product": _cef_unescape(product),
            "vendor_product_version": _cef_unescape(product_version),
            "vendor_event_description": _cef_unescape(name),
            "event_source_product": "unifi_network",
            "event_id": _cef_unescape(signature),
            "unifi_cef_version": cef_version,
        }
    )
    _set(out, "event_code", _integer(signature))
    _set(out, "vendor_event_severity_level", _integer(severity_value))

    controller = fields.get("UNIFIhost") or out.get("unifi_rfc3164_relay")
    _set(out, "event_observer_hostname", controller)
    _set(out, "event_reporter", out.get("unifi_rfc3164_relay") or controller)
    _set(out, "event_source", controller)
    _set(out, "unifi_site_code", fields.get("UNIFIsite"))
    _set(out, "event_created", fields.get("UNIFIutcTime"))
    _set(out, "source_ip", _ip(fields.get("UNIFIclientIp")))
    _set(out, "source_mac", _mac(fields["UNIFIclientMac"]) if fields.get("UNIFIclientMac") else None)
    _set(out, "source_hostname", fields.get("UNIFIclientHostname") or fields.get("UNIFIclientAlias"))
    _set(out, "network_name", fields.get("UNIFInetworkName"))
    _set(out, "network_cidr", fields.get("UNIFInetworkSubnet"))
    _set(out, "network_vlan", _integer(fields.get("UNIFInetworkVlan")))
    _set(out, "event_duration", _duration(fields.get("UNIFIduration")))
    _set(out, "unifi_client_bytes_up", _bytes(fields.get("UNIFIusageUp")))
    _set(out, "unifi_client_bytes_down", _bytes(fields.get("UNIFIusageDown")))
    _set(out, "unifi_switch_speed", fields.get("UNIFIlinkSpeed"))
    _set(out, "vendor_event_description", fields.get("msg") or out.get("vendor_event_description"))

    prefix = "UNIFIconnectedToDevice" if signature == "403" else "UNIFIlastConnectedToDevice"
    _set(out, "destination_hostname", fields.get(prefix + "Name"))
    _set(out, "destination_ip", _ip(fields.get(prefix + "Ip")))
    _set(out, "destination_mac", _mac(fields[prefix + "Mac"]) if fields.get(prefix + "Mac") else None)
    _set(out, "destination_device_model", fields.get(prefix + "Model"))
    _set(out, "destination_os_version", fields.get(prefix + "Version"))
    _set(out, "unifi_switch_port", _integer(fields.get(prefix + "Port")))

    if signature in CEF_EVENTS:
        out["event_action"], out["unifi_event_type"] = CEF_EVENTS[signature]

    cef_severity = _integer(severity_value)
    if cef_severity is not None and 0 <= cef_severity <= 10:
        normalized = (
            "debug" if cef_severity == 0 else "info" if cef_severity <= 3 else "notice" if cef_severity == 4
            else "warning" if cef_severity <= 6 else "error" if cef_severity <= 8 else "critical"
        )
        _apply_severity(out, normalized)

    _common_network_gim(out)
    return out


def _parse_device(payload: str, out: dict[str, Any]) -> dict[str, Any]:
    match = DEVICE_RE.match(payload)
    if not match:
        out["unifi_parse_error"] = "unrecognized_header"
        return out

    groups = match.groupdict()
    host_mac = _mac(groups["mac"])
    out.update(
        {
            "unifi_log_format": "syslog",
            "unifi_parse_status": "unsupported",
            "event_source_product": "unifi_device",
            "event_source": groups["host"],
            "host_name": groups["host"],
            "host_mac": host_mac,
            "host_device_vendor": "Ubiquiti",
            "host_device_model": groups["model"],
            "host_os_version": groups["version"],
            "unifi_device_mac": host_mac,
            "unifi_device_model": groups["model"],
            "unifi_device_version": groups["version"],
        }
    )
    body = groups["body"].lstrip()
    if body.startswith(":"):
        body = body[1:].lstrip()

    first = PROCESS_RE.match(body)
    if first and first.group("process") in {"mcad", "kernel", "hostapd", "stahtd", "logread", "wevent"}:
        process, pid, body = first.group("process"), first.group("pid"), first.group("body")
        second = PROCESS_RE.match(body)
        if second and process == "mcad":
            process, pid, body = second.group("process"), second.group("pid"), second.group("body")
        out["process_name"] = process
        _set(out, "process_pid", _integer(pid))

    port = PORT_LINK_RE.fullmatch(body)
    stp = PORT_STP_RE.fullmatch(body)
    wlan = WLAN_RE.fullmatch(body)
    if port:
        state = port.group("state").lower()
        out.update(
            {
                "unifi_parse_status": "parsed",
                "unifi_switch_port": int(port.group("port")),
                "unifi_switch_state": state,
                "event_action": state,
                "unifi_event_type": f"network.port.{state}",
            }
        )
    elif stp:
        state = stp.group("to").lower()
        out.update(
            {
                "unifi_parse_status": "parsed",
                "unifi_switch_port": int(stp.group("port")),
                "unifi_switch_previous_state": stp.group("from").lower(),
                "unifi_switch_state": state,
                "event_action": state,
                "unifi_event_type": f"network.port.{state}",
            }
        )
    elif wlan:
        action = "connected" if wlan.group("state").lower() == "associated" else "disconnected"
        out.update(
            {
                "unifi_parse_status": "parsed",
                "unifi_wlan_interface": wlan.group("interface"),
                "source_mac": _mac(wlan.group("client")),
                "destination_mac": host_mac,
                "destination_hostname": groups["host"],
                "event_action": action,
                "unifi_event_type": f"network.client.{action}",
            }
        )
        _common_network_gim(out)
    elif "ace_reporter.mesh_halt_timeout(): Mesh halt expired" in body:
        out.update(
            {
                "unifi_parse_status": "parsed",
                "event_action": "timeout",
                "unifi_mesh_state": "halted",
                "unifi_mesh_timeout": True,
                "unifi_event_type": "wireless.mesh.timeout",
            }
        )
    elif "ace_reporter.reporter_handle_response_json(): [reboot] reboot" in body:
        out.update(
            {"unifi_parse_status": "parsed", "event_action": "reboot", "unifi_event_type": "device.reboot"}
        )
    return out


def parse_message(raw: str) -> dict[str, Any]:
    """Parse one raw message and return stable fields suitable for assertions."""

    raw = raw.rstrip("\r\n")
    out: dict[str, Any] = {
        "message": raw,
        "full_message": raw,
        "unifi_parse_status": "malformed",
        "unifi_schema_version": "gim-7.1",
        "unifi_integration_version": "0.1.0",
    }
    payload = raw
    pri = re.match(r"^<(\d{1,3})>(.*)$", payload)
    if pri:
        priority = int(pri.group(1))
        payload = pri.group(2)
        out["unifi_syslog_priority"] = priority
        out["unifi_syslog_facility"] = priority // 8
        out["unifi_syslog_severity_code"] = priority % 8
        _apply_severity(out, SYSLOG_SEVERITY[priority % 8])

    rfc3164 = RFC3164_RE.match(payload)
    if rfc3164:
        out["unifi_rfc3164_timestamp"] = rfc3164.group("stamp")
        out["unifi_rfc3164_relay"] = rfc3164.group("relay")
        payload = rfc3164.group("payload")

    if payload.startswith("CEF:"):
        return _parse_cef(payload, out)
    return _parse_device(payload, out)
