from __future__ import annotations

import csv
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_references_existing_rules() -> None:
    pipeline = (ROOT / "pipelines" / "unifi-gim.pipeline").read_text(encoding="utf-8")
    references = set(re.findall(r'^\s*rule "([^"]+)"', pipeline, re.MULTILINE))
    sources = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "pipelines" / "rules").glob("*.rule"))
    definitions = set(re.findall(r'^rule "([^"]+)"', sources, re.MULTILINE))
    assert references == definitions


def test_rules_never_remove_fields() -> None:
    sources = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "pipelines" / "rules").glob("*.rule"))
    assert "remove_field" not in sources
    assert 'set_field("full_message"' in sources


def test_cef_parser_uses_graylog_7_compatible_arguments() -> None:
    source = (ROOT / "pipelines" / "rules" / "10-parse-cef.rule").read_text(encoding="utf-8")
    assert "parse_cef(to_string(capture[\"0\"]), true)" in source
    assert "use_full_names:" not in source


def test_cef_and_gim_severity_lookups_are_complete() -> None:
    with (ROOT / "lookups" / "cef_severity.csv").open(encoding="utf-8", newline="") as handle:
        cef = list(csv.DictReader(handle))
    with (ROOT / "lookups" / "gim_severity.csv").open(encoding="utf-8", newline="") as handle:
        gim = list(csv.DictReader(handle))
    assert {int(row["key"]) for row in cef} == set(range(11))
    assert {row["unifi_severity"] for row in gim} == {
        "debug", "info", "notice", "warning", "error", "critical"
    }
    assert {int(row["event_severity_level"]) for row in gim} == set(range(1, 6))


def test_installable_events_are_disabled() -> None:
    events = json.loads((ROOT / "events" / "event-definitions.json").read_text(encoding="utf-8"))
    assert len(events) == 4
    assert all(event["enabled"] is False for event in events)


def test_dashboards_and_streams_have_stable_unique_ids() -> None:
    streams = json.loads((ROOT / "streams" / "streams.json").read_text(encoding="utf-8"))
    dashboards = json.loads((ROOT / "dashboards" / "dashboards.json").read_text(encoding="utf-8"))
    ids = [item["id"] for item in streams + dashboards]
    assert len(ids) == len(set(ids))
    assert len(dashboards) == 4
