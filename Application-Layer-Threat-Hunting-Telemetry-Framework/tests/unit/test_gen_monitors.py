"""Lint tests for generated monitors and dashboards (Req 11.1, 11.2, 5.7, 6.6)."""

from __future__ import annotations

import json
import re

import yaml

from labcommon.schema import DetectionConfig
from tools import gen_monitors as gm

CFG = DetectionConfig.load()
RAW = yaml.safe_load((gm.ROOT / "config" / "detections.yaml").read_text())


def _files():
    return {p: t for p, t in gm.generate(CFG).items()}


def test_generated_files_are_current_and_one_monitor_per_scenario():
    outputs = _files()
    monitors = sorted(p.stem for p in outputs if p.parent == gm.MONITORS_DIR)
    assert monitors == sorted(gm.SCENARIOS)
    assert gm.main(["--check"]) == 0, "run python -m tools.gen_monitors"
    assert sorted(p.stem for p in gm.MONITORS_DIR.glob("*.json")) == sorted(gm.SCENARIOS)


def test_no_lab_fields_referenced():
    for path, text in _files().items():
        assert not re.search(r"\blab\.", text), path


def test_bola_thresholds_match_config():
    mon = json.loads((gm.MONITORS_DIR / "bola_enumeration.json").read_text())
    assert mon["monitor_type"] == "bucket_level_monitor"
    q = mon["inputs"][0]["search"]["query"]
    b = RAW["bola"]
    script = mon["triggers"][0]["bucket_level_trigger"]["condition"]["script"]["source"]
    assert f"distinct_ids > {b['distinct_ids_threshold']}" in script
    assert f"> {b['error_ratio_threshold']}" in script
    assert f"distinct_ids > {b['retry_suppression_max_ids']}" in script
    assert q["query"]["bool"]["must_not"][0]["terms"]["user.roles"] == b["excluded_roles"]
    comp = q["aggregations"]["composite_agg"]
    assert comp["composite"]["sources"][2]["window"]["date_histogram"]["fixed_interval"] == f"{b['window_minutes']}m"
    assert "precision_threshold" in comp["aggregations"]["distinct_ids"]["cardinality"]
    assert q["query"]["bool"]["filter"][1]["range"]["@timestamp"]["gte"] == f"now-{b['lookback_minutes']}m"


def test_jwt_and_ssrf_monitors_match_config():
    jwt = json.loads((gm.MONITORS_DIR / "jwt_abuse.json").read_text())
    assert jwt["monitor_type"] == "query_level_monitor" and len(jwt["triggers"]) == 3
    j = RAW["jwt"]
    assert jwt["inputs"][0]["search"]["query"]["query"]["bool"]["filter"][1]["range"]["@timestamp"]["gte"] == f"now-{j['hijack_window_minutes']}m"
    assert f">= {j['min_distinct_client_pairs']}" in jwt["triggers"][2]["query_level_trigger"]["condition"]["script"]["source"]

    ssrf = json.loads((gm.MONITORS_DIR / "ssrf_egress.json").read_text())
    should = ssrf["inputs"][0]["search"]["query"]["query"]["bool"]["filter"][2]["bool"]["should"]
    cidrs = [c["term"]["destination.ip"] for c in should if "destination.ip" in c.get("term", {})]
    hosts = [c["terms"]["destination.domain"] for c in should if "terms" in c][0]
    assert cidrs == RAW["ssrf"]["internal_cidrs"] and hosts == RAW["ssrf"]["internal_hostnames"]


def test_dashboards_have_stable_ids_and_index_pattern():
    for scenario in gm.SCENARIOS:
        objs = [json.loads(line) for line in (gm.DASHBOARDS_DIR / f"{scenario}.ndjson").read_text().splitlines()]
        assert any(o["type"] == "index-pattern" and o["attributes"]["title"] == "appsec-telemetry-*" for o in objs)
        assert sum(o["type"] == "dashboard" for o in objs) == 1
        assert all(o["id"] for o in objs)
