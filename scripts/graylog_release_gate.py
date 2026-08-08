"""Import a pack into Graylog, replay fixtures over UDP, and assert results."""

from __future__ import annotations

import argparse
import base64
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class GraylogAPIError(RuntimeError):
    """An API response that includes Graylog's diagnostic body."""


def request(
    base: str,
    user: str,
    password: str,
    method: str,
    path: str,
    body: Any = None,
    accept: str = "application/json",
) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    req.add_header("Accept", accept)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Requested-By", "graylog-unifi-gim-release-gate")
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            content = response.read()
            if not content:
                return None
            if response.headers.get_content_type() == "application/json":
                return json.loads(content)
            return content.decode().strip()
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace").strip()
        raise GraylogAPIError(f"{method} {path} failed with HTTP {error.code}: {detail}") from error


def wait_ready(base: str, user: str, password: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status = request(
                base,
                user,
                password,
                "GET",
                "/api/system/lbstatus",
                accept="text/plain",
            )
            state = status.get("status") if isinstance(status, dict) else status
            if state in {"ALIVE", "THROTTLED"}:
                return
        except (OSError, urllib.error.URLError, json.JSONDecodeError, GraylogAPIError) as error:
            last_error = error
        time.sleep(5)
    raise RuntimeError(f"Graylog did not become ready: {last_error}")


def import_pack(base: str, user: str, password: str, pack: dict[str, Any], udp_port: int) -> None:
    request(base, user, password, "POST", "/api/system/content_packs", pack)
    parameters: dict[str, Any] = {}
    if pack["parameters"]:
        parameters = {"udp_bind_address": "0.0.0.0", "udp_port": udp_port}
    request(
        base,
        user,
        password,
        "POST",
        f"/api/system/content_packs/{pack['id']}/{pack['rev']}/installations",
        {
            "entity": {
                "comment": "Automated 0.1 release gate",
                "parameters": parameters,
            }
        },
    )


def replay(root: Path, host: str, port: int) -> int:
    messages = []
    manifest = json.loads((root / "tests" / "fixtures" / "manifest.json").read_text(encoding="utf-8"))
    for fixture in manifest["fixtures"]:
        messages.append((root / "samples" / "raw" / f"{fixture['id']}.log").read_bytes().rstrip(b"\r\n"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for message in messages:
            sender.sendto(message, (host, port))
    return len(messages)


def assert_search(base: str, user: str, password: str, expected: int) -> None:
    deadline = time.monotonic() + 120
    query = urllib.parse.quote('unifi_integration_version:"0.1.0"')
    while time.monotonic() < deadline:
        result = request(base, user, password, "GET", f"/api/search/universal/relative?query={query}&range=300&limit=100")
        if result.get("total_results", 0) >= expected:
            messages = [entry["message"] for entry in result.get("messages", [])]
            statuses = {message.get("unifi_parse_status") for message in messages}
            if {"parsed", "unsupported", "malformed"} <= statuses:
                return
        time.sleep(5)
    raise AssertionError(f"expected at least {expected} replayed messages with all parse statuses")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--variant", choices=["with-input", "assets-only"], default="with-input")
    parser.add_argument("--url", default="http://127.0.0.1:9000")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--udp-host", default="127.0.0.1")
    parser.add_argument("--udp-port", type=int, default=1515)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    pack_path = args.root / "content-pack" / f"graylog-unifi-gim-0.1.0-{args.variant}.json"
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    if args.validate_only:
        assert pack["v"] == 1 and pack["entities"]
        return 0
    wait_ready(args.url, args.user, args.password, args.timeout)
    import_pack(args.url, args.user, args.password, pack, args.udp_port)
    if args.variant == "assets-only":
        print("Assets-only import validated; UDP replay requires a separately configured input.")
        return 0
    expected = replay(args.root, args.udp_host, args.udp_port)
    assert_search(args.url, args.user, args.password, expected)
    print(f"validated {args.variant}: {expected} fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
