from __future__ import annotations

from email.message import Message
from unittest.mock import patch

from scripts.graylog_release_gate import import_pack, request, validate_rules, wait_input_available


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


def test_installation_uses_graylog_7_entity_wrapper() -> None:
    pack = {"id": "pack-id", "rev": 1, "parameters": [{"name": "udp_port"}]}
    with patch("scripts.graylog_release_gate.request") as api_request:
        import_pack("http://graylog", "admin", "admin", pack, 1515)
    installation_body = api_request.call_args_list[1].args[5]
    assert installation_body == {
        "entity": {
            "comment": "Automated 0.1 release gate",
            "parameters": {
                "udp_bind_address": {"@type": "string", "@value": "0.0.0.0"},
                "udp_port": {"@type": "integer", "@value": 1515},
            },
        }
    }


def test_wait_input_available_matches_installed_input() -> None:
    inputs = {"inputs": [{"id": "input-id", "title": "UniFi - Mixed Raw UDP"}]}
    with patch("scripts.graylog_release_gate.request", side_effect=[inputs, None]) as api_request:
        result = wait_input_available(
            "http://graylog", "admin", "admin", timeout=1, settle_seconds=0
        )
    assert result == "input-id"
    assert api_request.call_args_list[1].args[3:5] == (
        "PUT",
        "/api/cluster/inputstates/input-id",
    )


def test_validate_rules_uses_graylog_parse_endpoint() -> None:
    pack = {
        "entities": [
            {
                "type": {"name": "pipeline_rule"},
                "data": {
                    "title": {"@value": "Rule title"},
                    "description": {"@value": "Rule description"},
                    "source": {"@value": 'rule "Rule title" when true then end'},
                },
            },
            {"type": {"name": "stream"}, "data": {}},
        ]
    }
    with patch("scripts.graylog_release_gate.request") as api_request:
        validate_rules("http://graylog", "admin", "admin", pack)
    assert api_request.call_args.args[3:5] == (
        "POST",
        "/api/system/pipelines/rule/parse",
    )
