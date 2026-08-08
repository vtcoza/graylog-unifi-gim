"""Deterministic sanitizer for locally held raw UniFi exports."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path


MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])|"
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
IP_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")


def _number(namespace: str, value: str, modulus: int) -> int:
    digest = hashlib.sha256(f"{namespace}\0{value.lower()}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % modulus


def sanitize_mac(value: str) -> str:
    number = _number("mac", value, 1 << 40)
    octets = [0x02] + list(number.to_bytes(5, "big"))
    rendered = ":".join(f"{part:02x}" for part in octets)
    return rendered.replace(":", "") if ":" not in value else rendered


def sanitize_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    number = _number("ip", value, 254) + 1
    subnet = _number("subnet", value, 3)
    return f"192.0.{2 + subnet * 49}.{number}"


def sanitize_message(message: str) -> str:
    message = MAC_RE.sub(lambda match: sanitize_mac(match.group()), message)
    return IP_RE.sub(lambda match: sanitize_ip(match.group()), message)


def iter_csv_messages(path: Path) -> Iterable[str]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("message"):
                yield row["message"]

