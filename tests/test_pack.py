from __future__ import annotations

import json
from pathlib import Path

from graylog_unifi_gim.pack import build_pack


ROOT = Path(__file__).resolve().parents[1]


def test_pack_generation_is_deterministic() -> None:
    assert build_pack(ROOT, "with-input") == build_pack(ROOT, "with-input")
    assert build_pack(ROOT, "assets-only") == build_pack(ROOT, "assets-only")


def test_pack_variants_have_distinct_ids_and_only_one_has_input() -> None:
    with_input = build_pack(ROOT, "with-input")
    assets_only = build_pack(ROOT, "assets-only")
    assert with_input["id"] != assets_only["id"]
    assert sum(entity["type"]["name"] == "input" for entity in with_input["entities"]) == 1
    assert sum(entity["type"]["name"] == "input" for entity in assets_only["entities"]) == 0
    assert {parameter["name"] for parameter in with_input["parameters"]} == {"udp_bind_address", "udp_port"}


def test_generated_artifacts_match_builder() -> None:
    for variant in ("with-input", "assets-only"):
        path = ROOT / "content-pack" / f"graylog-unifi-gim-0.1.0-{variant}.json"
        assert json.loads(path.read_text(encoding="utf-8")) == build_pack(ROOT, variant)


def test_pack_contains_required_asset_types() -> None:
    pack = build_pack(ROOT, "with-input")
    types = {entity["type"]["name"] for entity in pack["entities"]}
    assert {
        "dashboard", "event_definition", "grok_pattern", "input", "lookup_adapter",
        "lookup_cache", "lookup_table", "pipeline", "pipeline_rule", "stream"
    } <= types
