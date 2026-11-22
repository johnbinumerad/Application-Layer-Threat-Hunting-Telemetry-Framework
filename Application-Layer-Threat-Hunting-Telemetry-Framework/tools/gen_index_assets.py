"""Generate OpenSearch index template and ingest pipeline (Req 3.8, 7.4, 8.6, 11.2).

Reads ``config/field_mapping.yaml`` and ``config/ip_enrichment.yaml`` and writes
``infra/opensearch/index_template.json`` and ``infra/opensearch/ingest_pipeline.json``.

Usage: python -m tools.gen_index_assets [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

import yaml

from labcommon.enrich import load_table, painless_script_processor

ROOT = Path(__file__).resolve().parent.parent
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"
ENRICHMENT = ROOT / "config" / "ip_enrichment.yaml"
OUT_DIR = ROOT / "infra" / "opensearch"
TEMPLATE_PATH = OUT_DIR / "index_template.json"
PIPELINE_PATH = OUT_DIR / "ingest_pipeline.json"

INDEX_PATTERN = "appsec-telemetry-*"
PIPELINE_NAME = "appsec-enrich"
TEMPLATE_NAME = "appsec-telemetry"

_TYPES = {"keyword", "text", "date", "long", "boolean", "ip"}


def _leaf(ftype: str) -> dict[str, Any]:
    if ftype not in _TYPES:
        raise ValueError(f"unsupported field type: {ftype}")
    if ftype == "text":
        # Searchable only; never aggregatable (no fielddata, no keyword subfield).
        return {"type": "text", "fielddata": False}
    if ftype == "date":
        return {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
    return {"type": ftype}


def build_properties(fields: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Expand dotted ECS names into nested ``properties``."""
    root: dict[str, Any] = {}
    for name in sorted(fields):
        parts = name.split(".")
        node = root
        for part in parts[:-1]:
            entry = node.setdefault(part, {"properties": {}})
            if "properties" not in entry:
                raise ValueError(f"field {name!r} conflicts with leaf {part!r}")
            node = entry["properties"]
        if parts[-1] in node:
            raise ValueError(f"field {name!r} conflicts with an existing object field")
        node[parts[-1]] = _leaf(str(fields[name]["type"]))
    return root


def build_template(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "index_patterns": [INDEX_PATTERN],
        "priority": 100,
        "template": {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "1s",
                    "default_pipeline": PIPELINE_NAME,
                }
            },
            "mappings": {
                "dynamic": False,
                "properties": build_properties(mapping["fields"]),
            },
        },
        "_meta": {"generated_by": "tools/gen_index_assets.py", "name": TEMPLATE_NAME},
    }


def build_pipeline() -> dict[str, Any]:
    table = load_table(ENRICHMENT)
    return {
        "description": "Lab IP to ASN/geo enrichment (generated from config/ip_enrichment.yaml)",
        "processors": [
            # Collector output may carry flat dotted keys; expand so the script sees ctx.source.ip.
            {"dot_expander": {"field": "source.ip", "ignore_failure": True}},
            painless_script_processor(table),
        ],
    }


def render(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def generate() -> dict[Path, str]:
    mapping = yaml.safe_load(FIELD_MAPPING.read_text())
    return {
        TEMPLATE_PATH: render(build_template(mapping)),
        PIPELINE_PATH: render(build_pipeline()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = ap.parse_args(argv)
    outputs = generate()
    if args.check:
        stale = [str(p) for p, text in outputs.items() if not p.exists() or p.read_text() != text]
        if stale:
            print("stale generated files: " + ", ".join(stale), file=sys.stderr)
            return 1
        return 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path, text in outputs.items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
