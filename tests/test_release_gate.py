from __future__ import annotations

from email.message import Message
from unittest.mock import patch

from scripts.graylog_release_gate import request


class FakeResponse:
    def __init__(self, body: bytes, content_type: str) -> None:
        self.body = body
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def test_request_accepts_plain_text_lbstatus() -> None:
    response = FakeResponse(b"ALIVE\n", "text/plain")
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        assert request("http://graylog", "admin", "admin", "GET", "/api/system/lbstatus", accept="text/plain") == "ALIVE"
    assert urlopen.call_args.args[0].get_header("Accept") == "text/plain"


def test_request_decodes_json_api_response() -> None:
    response = FakeResponse(b'{"total_results": 1}', "application/json")
    with patch("urllib.request.urlopen", return_value=response):
        assert request("http://graylog", "admin", "admin", "GET", "/api/search") == {"total_results": 1}
