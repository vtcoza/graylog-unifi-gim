"""Deterministic Graylog v1 content-pack builder."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any


NAMESPACE = uuid.UUID("8192bf0f-48ca-57b7-8b57-b4f09f5383fb")
PACK_IDS = {
    "with-input": "be8c8625-e256-539a-8809-13040a73307a",
    "assets-only": "caf0ee1f-5a9c-5c58-92dd-d5e9c0e5b19f",
}
RAW_STREAM_ID = "78261a1d-0113-5fad-8385-0ca42baf9188"
CONSTRAINTS = [{"type": "server-version", "version": ">=7.1.0"}]


def _id(kind: str, name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{kind}:{name}"))


def _typed(value: Any, kind: str | None = None) -> dict[str, Any]:
    if kind is None:
        kind = (
            "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "string"
        )
    return {"@type": kind, "@value": value}


def _entity(kind: str, entity_id: str, data: dict[str, Any], version: str = "1") -> dict[str, Any]:
    return {
        "v": "1",
        "type": {"name": kind, "version": version},
        "id": entity_id,
        "data": data,
        "constraints": CONSTRAINTS,
    }


def _rule_entities(root: Path) -> list[dict[str, Any]]:
    entities = []
    for path in sorted((root / "pipelines" / "rules").glob("*.rule")):
        source = path.read_text(encoding="utf-8").rstrip() + "\n"
        title = source.split('rule "', 1)[1].split('"', 1)[0]
        entities.append(
            _entity(
                "pipeline_rule",
                _id("pipeline_rule", title),
                {
                    "title": _typed(title),
                    "description": _typed(f"Generated from pipelines/rules/{path.name}"),
                    "source": _typed(source),
                },
            )
        )
    return entities


def _pipeline_entity(root: Path) -> dict[str, Any]:
    source = (root / "pipelines" / "unifi-gim.pipeline").read_text(encoding="utf-8").rstrip() + "\n"
    return _entity(
        "pipeline",
        _id("pipeline", "UniFi GIM"),
        {
            "title": _typed("UniFi GIM"),
            "description": _typed("Mixed CEF/syslog parsing, GIM normalization, enrichment, and routing."),
            "source": _typed(source),
            "connected_streams": [_typed(RAW_STREAM_ID)],
        },
    )


def _grok_entities(root: Path) -> list[dict[str, Any]]:
    entities = []
    for path in sorted((root / "grok").glob("*.grok")):
        entities.append(
            _entity(
                "grok_pattern",
                _id("grok_pattern", path.stem),
                {"name": _typed(path.stem), "pattern": _typed(path.read_text(encoding="utf-8").strip())},
            )
        )
    return entities


def _stream_entities(root: Path) -> list[dict[str, Any]]:
    streams = json.loads((root / "streams" / "streams.json").read_text(encoding="utf-8"))
    entities = []
    for stream in streams:
        rules = []
        for rule in stream["rules"]:
            rules.append(
                {
                    "type": _typed(rule["type"]),
                    "field": _typed(rule["field"]),
                    "value": _typed(rule["value"]),
                    "inverted": _typed(rule["inverted"]),
                    "description": _typed("Managed by Graylog UniFi GIM"),
                }
            )
        entities.append(
            _entity(
                "stream",
                stream["id"],
                {
                    "alarm_callbacks": [],
                    "outputs": [],
                    "remove_matches": _typed(stream["remove_matches"]),
                    "title": _typed(stream["title"]),
                    "stream_rules": rules,
                    "alert_conditions": [],
                    "matching_type": _typed(stream["matching_type"]),
                    "disabled": _typed(False),
                    "description": _typed(stream["description"]),
                    "default_stream": _typed(False),
                },
            )
        )
    return entities


def _lookup_entities() -> list[dict[str, Any]]:
    specs = [
        ("unifi_cef_severity", "cef_severity.csv", "key", "unifi_severity"),
        ("unifi_gim_severity", "gim_severity.csv", "unifi_severity", "event_severity"),
        ("unifi_gim_severity_level", "gim_severity.csv", "unifi_severity", "event_severity_level"),
        ("unifi_cef_event_type", "cef_events.csv", "code", "unifi_event_type"),
    ]
    entities: list[dict[str, Any]] = []
    for name, filename, key, value in specs:
        adapter_id = _id("lookup_adapter", name)
        cache_id = _id("lookup_cache", name)
        entities.append(
            _entity(
                "lookup_adapter",
                adapter_id,
                {
                    "_scope": _typed("DEFAULT"),
                    "name": _typed(f"{name}-adapter"),
                    "title": _typed(f"UniFi {name} adapter"),
                    "description": _typed("CSV data mounted read-only from the content-pack repository."),
                    "configuration": {
                        "type": _typed("csvfile"),
                        "path": _typed(f"/usr/share/graylog/data/unifi-gim/{filename}"),
                        "separator": _typed(","),
                        "quotechar": _typed('"'),
                        "key_column": _typed(key),
                        "value_column": _typed(value),
                        "check_interval": _typed(60, "long"),
                        "case_insensitive_lookup": _typed(False),
                    },
                },
            )
        )
        entities.append(
            _entity(
                "lookup_cache",
                cache_id,
                {
                    "_scope": _typed("DEFAULT"),
                    "name": _typed(f"{name}-cache"),
                    "title": _typed(f"UniFi {name} cache"),
                    "description": _typed("In-memory cache for UniFi normalization data."),
                    "configuration": {
                        "type": _typed("guava_cache"),
                        "max_size": _typed(1000),
                        "expire_after_access": _typed(0, "long"),
                        "expire_after_access_unit": _typed("SECONDS"),
                        "expire_after_write": _typed(60, "long"),
                        "expire_after_write_unit": _typed("SECONDS"),
                    },
                },
            )
        )
        entities.append(
            _entity(
                "lookup_table",
                _id("lookup_table", name),
                {
                    "_scope": _typed("DEFAULT"),
                    "name": _typed(name),
                    "title": _typed(f"UniFi {name}"),
                    "description": _typed("UniFi GIM normalization lookup."),
                    "default_single_value": _typed(""),
                    "default_single_value_type": _typed("STRING"),
                    "default_multi_value": _typed(""),
                    "default_multi_value_type": _typed("NULL"),
                    "data_adapter_name": _typed(adapter_id),
                    "cache_name": _typed(cache_id),
                },
            )
        )
    return entities


def _event_entities(root: Path) -> list[dict[str, Any]]:
    definitions = json.loads((root / "events" / "event-definitions.json").read_text(encoding="utf-8"))
    entities = []
    for item in definitions:
        # Graylog's aggregation-v1 entity shape is retained as typed source data.
        config = {
            "type": _typed("aggregation-v1"),
            "query": _typed(item["query"]),
            "query_parameters": [],
            "streams": [_typed("0a57ef15-0a43-565e-b927-1109b7df1d29")],
            "group_by": [_typed(field) for field in item["group_by"]],
            "series": [
                {
                    "id": _typed("count"),
                    "function": _typed("count"),
                    "field": _typed("")
                }
            ],
            "conditions": {
                "expression": {
                    "expr": _typed(">="),
                    "left": {"expr": _typed("number-ref"), "ref": _typed("count")},
                    "right": {"expr": _typed("number"), "value": _typed(item["threshold"], "double")}
                }
            },
            "search_within_ms": _typed(item["search_within_ms"], "long"),
            "execute_every_ms": _typed(item["execute_every_ms"], "long"),
        }
        entities.append(
            _entity(
                "event_definition",
                item["id"],
                {
                    "title": _typed(item["title"]),
                    "description": _typed(item["description"]),
                    "priority": _typed(item["priority"]),
                    "alert": _typed(False),
                    "config": config,
                    "field_spec": {},
                    "key_spec": [],
                    "notification_settings": {"grace_period_ms": _typed(0, "long"), "backlog_size": _typed(0)},
                    "notifications": [],
                    "remediation_steps": _typed("Review the source message and affected UniFi device."),
                    "storage": [],
                    "enabled": _typed(False),
                },
            )
        )
    return entities


def _dashboard_entities(root: Path) -> list[dict[str, Any]]:
    dashboards = json.loads((root / "dashboards" / "dashboards.json").read_text(encoding="utf-8"))
    entities = []
    for item in dashboards:
        query_id = _id("dashboard_query", item["title"])
        search_types = []
        widgets = []
        widget_mapping: dict[str, list[str]] = {}
        positions: dict[str, dict[str, int]] = {}
        widget_titles: dict[str, str] = {}
        for index, widget in enumerate(item["widgets"]):
            widget_id = _id("dashboard_widget", f'{item["title"]}:{widget["title"]}')
            search_type_id = _id("dashboard_search_type", f'{item["title"]}:{widget["title"]}')
            group_by = widget.get("group_by", "unifi_event_type")
            query = {"type": "elasticsearch", "query_string": widget["query"]}
            row_pivot = {"fields": [group_by], "type": "values", "config": {"limit": 10}}
            series = [{"config": {"name": "Message count"}, "function": "count()"}]
            sort = [{"type": "series", "field": "count()", "direction": "Descending"}]
            search_types.append(
                {
                    "query": query,
                    "name": "chart",
                    "timerange": {"range": 86400, "type": "relative"},
                    "column_limit": None,
                    "streams": [],
                    "stream_categories": [],
                    "row_limit": 10,
                    "series": [{"type": "count", "id": "count()", "field": None}],
                    "filter": None,
                    "rollup": True,
                    "row_groups": [{"type": "values", "fields": [group_by], "limit": 10}],
                    "type": "pivot",
                    "id": search_type_id,
                    "filters": [],
                    "column_groups": [],
                    "sort": sort,
                }
            )
            widgets.append(
                {
                    "id": widget_id,
                    "type": "aggregation",
                    "filter": None,
                    "filters": [],
                    "timerange": {"range": 86400, "type": "relative"},
                    "query": query,
                    "streams": [],
                    "stream_categories": [],
                    "config": {
                        "visualization": "table" if widget["type"] == "messages" else "bar",
                        "column_limit": None,
                        "event_annotation": False,
                        "row_limit": 10,
                        "row_pivots": [row_pivot],
                        "series": series,
                        "rollup": True,
                        "column_pivots": [],
                        "visualization_config": None,
                        "formatting_settings": None,
                        "sort": sort,
                    },
                    "description": widget["title"],
                    "context": None,
                }
            )
            widget_mapping[widget_id] = [search_type_id]
            positions[widget_id] = {
                "col": 1 if index % 2 == 0 else 7,
                "row": 1 + (index // 2) * 4,
                "height": 4,
                "width": 6,
            }
            widget_titles[widget_id] = widget["title"]
        data = {
            "summary": _typed(item["description"]),
            "search": {
                "queries": [
                    {
                        "id": query_id,
                        "timerange": {"range": 86400, "type": "relative"},
                        "filter": None,
                        "filters": [],
                        "query": {"type": "elasticsearch", "query_string": ""},
                        "search_types": search_types,
                    }
                ],
                "parameters": [],
                "requires": {},
                "owner": "admin",
                "created_at": "2026-01-01T00:00:00.000Z",
            },
            "created_at": "2026-01-01T00:00:00.000Z",
            "requires": {},
            "state": {
                query_id: {
                    "selected_fields": None,
                    "static_message_list_id": None,
                    "titles": {"tab": {"title": item["title"]}, "widget": widget_titles},
                    "widgets": widgets,
                    "widget_mapping": widget_mapping,
                    "positions": positions,
                    "formatting": {"highlighting": []},
                    "display_mode_settings": {"positions": {}},
                }
            },
            "properties": [],
            "owner": "admin",
            "title": _typed(item["title"]),
            "type": "DASHBOARD",
            "description": _typed(item["description"]),
        }
        entities.append(
            _entity("dashboard", item["id"], data, version="2")
        )
    return entities


def _input_entity() -> dict[str, Any]:
    return _entity(
        "input",
        _id("input", "UniFi Mixed Raw UDP"),
        {
            "title": _typed("UniFi - Mixed Raw UDP"),
            "type": _typed("org.graylog2.inputs.raw.udp.RawUDPInput"),
            "global": _typed(True),
            "configuration": {
                "bind_address": {"@type": "parameter", "@value": "udp_bind_address"},
                "port": {"@type": "parameter", "@value": "udp_port"},
                "recv_buffer_size": _typed(1048576),
                "number_worker_threads": _typed(2),
                "override_source": _typed(""),
                "charset_name": _typed("UTF-8"),
                "static_fields": {"unifi_ingest": _typed("true")},
            },
            "static_fields": {"unifi_ingest": _typed("true")},
        },
    )


def build_pack(root: Path, variant: str) -> dict[str, Any]:
    if variant not in PACK_IDS:
        raise ValueError(f"unknown pack variant: {variant}")
    entities = (
        _grok_entities(root)
        + _rule_entities(root)
        + [_pipeline_entity(root)]
        + _stream_entities(root)
        + _lookup_entities()
        + _event_entities(root)
        + _dashboard_entities(root)
    )
    parameters: list[dict[str, Any]] = []
    if variant == "with-input":
        entities.append(_input_entity())
        parameters = [
            {
                "name": "udp_bind_address",
                "title": "UDP bind address",
                "description": "Address used by the global Raw/Plaintext UDP input.",
                "type": "string",
                "default_value": "0.0.0.0",
            },
            {
                "name": "udp_port",
                "title": "UDP port",
                "description": "Port receiving mixed UniFi CEF and syslog messages.",
                "type": "integer",
                "default_value": 1515,
            },
        ]
    entities.sort(key=lambda entity: (entity["type"]["name"], entity["id"]))
    return {
        "v": 1,
        "id": PACK_IDS[variant],
        "rev": 1,
        "name": f"Graylog UniFi GIM 0.1 ({variant})",
        "summary": "Mixed UniFi OS CEF/syslog ingestion normalized to the Graylog Information Model.",
        "description": (
            "Evidence-gated UniFi integration for Graylog Open 7.1. Install only one variant. "
            "Lookup CSV files must be mounted as documented. Event definitions install disabled."
        ),
        "vendor": "Graylog UniFi GIM community",
        "url": "https://github.com/vtcoza/graylog-unifi-gim",
        "parameters": parameters,
        "entities": entities,
    }


def build_all(root: Path) -> list[Path]:
    output_dir = root / "content-pack"
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for variant in PACK_IDS:
        path = output_dir / f"graylog-unifi-gim-0.1.0-{variant}.json"
        content = json.dumps(build_pack(root, variant), indent=2, sort_keys=False, ensure_ascii=False) + "\n"
        path.write_text(content, encoding="utf-8", newline="\n")
        outputs.append(path)
    return outputs
