from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from graylog_unifi_gim.parser import parse_message


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests" / "fixtures" / "manifest.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"], ids=lambda item: item["id"])
def test_golden_fixture(fixture: dict[str, object]) -> None:
    fixture_id = str(fixture["id"])
    raw = (ROOT / "samples" / "raw" / f"{fixture_id}.log").read_text(encoding="utf-8").rstrip("\r\n")
    expected = json.loads((ROOT / "samples" / "expected" / f"{fixture_id}.json").read_text(encoding="utf-8"))
    actual = parse_message(raw)
    assert actual["message"] == raw
    assert actual["full_message"] == raw
    assert actual["unifi_parse_status"] == fixture["status"]
    for field, value in expected.items():
        assert actual.get(field) == value, f"{fixture_id}: {field}"


@pytest.mark.parametrize("fixture", [item for item in MANIFEST["fixtures"] if item["format"] == "cef"])
def test_cef_vendor_fields_are_never_removed(fixture: dict[str, object]) -> None:
    fixture_id = str(fixture["id"])
    raw = (ROOT / "samples" / "raw" / f"{fixture_id}.log").read_text(encoding="utf-8")
    actual = parse_message(raw)
    keys = re.findall(r"(?:^|\s)(UNIFI[A-Za-z0-9]+)=", raw)
    assert keys
    assert all(key in actual for key in keys)


def test_duplicate_messages_remain_independent_and_identical() -> None:
    raw = (ROOT / "samples" / "raw" / "syslog-port-down-pri.log").read_text(encoding="utf-8")
    first = parse_message(raw)
    second = parse_message(raw)
    assert first == second
    assert first is not second


def test_every_manifest_entry_has_raw_and_expected_files() -> None:
    ids = {str(item["id"]) for item in MANIFEST["fixtures"]}
    raw_ids = {path.stem for path in (ROOT / "samples" / "raw").glob("*.log")}
    expected_ids = {path.stem for path in (ROOT / "samples" / "expected").glob("*.json")}
    assert ids == raw_ids == expected_ids

