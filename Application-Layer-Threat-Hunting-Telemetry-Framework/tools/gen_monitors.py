"""Generate OpenSearch monitors and Dashboards saved objects (Req 11.1, 11.2, 5.7, 6.6).

Reads ``config/detections.yaml`` through ``labcommon.schema.DetectionConfig`` (single source of
truth for thresholds) and writes exactly one monitor per scenario to ``opensearch/monitors/`` and
one NDJSON saved-object bundle per scenario to ``opensearch/dashboards/``.

Detections never reference ``lab.*`` ground-truth fields.

Usage: python -m tools.gen_monitors [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from labcommon.schema import DetectionConfig

ROOT = Path(__file__).resolve().parent.parent
MONITORS_DIR = ROOT / "opensearch" / "monitors"
DASHBOARDS_DIR = ROOT / "opensearch" / "dashboards"

INDEX_PATTERN = "appsec-telemetry-*"
INDEX_PATTERN_ID = "appsec-telemetry-index-pattern"
SCENARIOS = ("bola_enumeration", "jwt_abuse", "ssrf_egress")
PRECISION_THRESHOLD = 3000
SCHEDULE = {"period": {"interval": 1, "unit": "MINUTES"}}


# ------------------------------------------------------------------ monitors
def _monitor(name: str, mtype: str, query: dict[str, Any], triggers: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "type": "monitor",
        "monitor_type": mtype,
        "name": name,
        "enabled": True,
        "schedule": SCHEDULE,
        "inputs": [{"search": {"indices": [INDEX_PATTERN], "query": query}}],
        "triggers": triggers,
    }


def build_bola(cfg: DetectionConfig) -> dict[str, Any]:
    b = cfg.bola
    # Painless numeric literals come straight from config/detections.yaml.
    script = (
        f"params.distinct_ids > {b.distinct_ids_threshold} "
        f"&& params.distinct_ids > {b.retry_suppression_max_ids} "
        f"&& params.total > 0 "
        f"&& ((double) (params.c403 + params.c404 + params.c_xtenant)) / params.total > {b.error_ratio_threshold}"
    )
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.dataset": "appsec.api"}},
                    {"range": {"@timestamp": {"gte": f"now-{b.lookback_minutes}m"}}},
                ],
                "must_not": [{"terms": {"user.roles": list(b.excluded_roles)}}],
            }
        },
        "aggregations": {
            "composite_agg": {
                "composite": {
                    "size": 1000,
                    "sources": [
                        {"user": {"terms": {"field": "user.id"}}},
                        {"endpoint": {"terms": {"field": "appsec.endpoint_template"}}},
                        {
                            "window": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "fixed_interval": f"{b.window_minutes}m",
                                    "offset": "0m",  # parameterized anchor offset
                                }
                            }
                        },
                    ],
                },
                "aggregations": {
                    "distinct_ids": {
                        "cardinality": {
                            "field": "appsec.resource_id",
                            "precision_threshold": PRECISION_THRESHOLD,
                        }
                    },
                    "c403": {"filter": {"term": {"http.response.status_code": 403}}},
                    "c404": {"filter": {"term": {"http.response.status_code": 404}}},
                    "c_xtenant": {"filter": {"term": {"appsec.authz.cross_tenant": True}}},
                },
            }
        },
    }
    trigger = {
        "bucket_level_trigger": {
            "name": "bola-enumeration",
            "severity": "2",
            "condition": {
                "buckets_path": {
                    "distinct_ids": "distinct_ids.value",
                    "total": "_count",
                    "c403": "c403._count",
                    "c404": "c404._count",
                    "c_xtenant": "c_xtenant._count",
                },
                "parent_bucket_path": "composite_agg",
                "script": {"source": script, "lang": "painless"},
            },
            "actions": [],
        }
    }
    return _monitor("bola_enumeration", "bucket_level_monitor", query, [trigger])


def _qtrigger(name: str, source: str, severity: str = "2") -> dict[str, Any]:
    return {
        "query_level_trigger": {
            "name": name,
            "severity": severity,
            "condition": {"script": {"source": source, "lang": "painless"}},
            "actions": [],
        }
    }


def build_jwt(cfg: DetectionConfig) -> dict[str, Any]:
    j = cfg.jwt
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.dataset": "appsec.api"}},
                    {"range": {"@timestamp": {"gte": f"now-{j.hijack_window_minutes}m"}}},
                ]
            }
        },
        "aggregations": {
            "forged_or_failed": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"appsec.jwt.alg": "none"}},
                            {"term": {"event.action": "jwt_validation_failed"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "expired_accepted": {
                "filter": {
                    "bool": {
                        "filter": [
                            {"term": {"appsec.jwt.expired": True}},
                            {"range": {"http.response.status_code": {"gte": 200, "lt": 300}}},
                        ]
                    }
                }
            },
            "jti_reuse": {
                "terms": {"field": "appsec.jwt.jti", "size": 1000},
                "aggregations": {"client_pairs": {"cardinality": {"field": "appsec.client_pair"}}},
            },
        },
    }
    t_c = (
        "def b = ctx.results[0].aggregations.jti_reuse.buckets; "
        "for (def x : b) { if (x.client_pairs.value >= "
        f"{j.min_distinct_client_pairs}) {{ return true; }} }} return false;"
    )
    triggers = [
        _qtrigger("jwt-alg-none-or-validation-failed", "ctx.results[0].aggregations.forged_or_failed.doc_count > 0"),
        _qtrigger("jwt-expired-accepted", "ctx.results[0].aggregations.expired_accepted.doc_count > 0"),
        _qtrigger("jwt-jti-multi-client", t_c),
    ]
    return _monitor("jwt_abuse", "query_level_monitor", query, triggers)


def build_ssrf(cfg: DetectionConfig) -> dict[str, Any]:
    s = cfg.ssrf
    internal = [
        {"term": {"destination.ip": cidr}} for cidr in s.internal_cidrs
    ]
    if s.internal_hostnames:
        internal.append({"terms": {"destination.domain": list(s.internal_hostnames)}})
    bool_q: dict[str, Any] = {
        "filter": [
            {"term": {"event.dataset": "appsec.egress"}},
            {"range": {"@timestamp": {"gte": "now-5m"}}},
            {"bool": {"should": internal, "minimum_should_match": 1}},
        ]
    }
    if s.allowed_destination_hosts:
        allow = list(s.allowed_destination_hosts)
        bool_q["must_not"] = [
            {"terms": {"destination.domain": allow}},
            {"terms": {"destination.address": allow}},
        ]
    query = {"size": 10, "query": {"bool": bool_q}}
    trigger = _qtrigger("ssrf-internal-egress", "ctx.results[0].hits.total.value > 0")
    return _monitor("ssrf_egress", "query_level_monitor", query, [trigger])


# ----------------------------------------------------------------- dashboards
def _ndjson(objs: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(o, sort_keys=True) + "\n" for o in objs)


def _index_pattern() -> dict[str, Any]:
    return {
        "id": INDEX_PATTERN_ID,
        "type": "index-pattern",
        "attributes": {"title": INDEX_PATTERN, "timeFieldName": "@timestamp"},
        "references": [],
    }


def _search(sid: str, title: str, query: str, columns: list[str]) -> dict[str, Any]:
    source = {
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "query": {"language": "kuery", "query": query},
        "filter": [],
    }
    return {
        "id": sid,
        "type": "search",
        "attributes": {
            "title": title,
            "columns": columns,
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source, sort_keys=True)},
        },
        "references": [
            {
                "id": INDEX_PATTERN_ID,
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
            }
        ],
    }


def _dashboard(did: str, title: str, search_ids: list[str]) -> dict[str, Any]:
    panels = [
        {
            "version": "1",
            "type": "search",
            "gridData": {"x": 0, "y": 15 * i, "w": 48, "h": 15, "i": str(i + 1)},
            "panelIndex": str(i + 1),
            "embeddableConfig": {},
            "panelRefName": f"panel_{i}",
        }
        for i in range(len(search_ids))
    ]
    return {
        "id": did,
        "type": "dashboard",
        "attributes": {
            "title": title,
            "hits": 0,
            "description": "",
            "panelsJSON": json.dumps(panels, sort_keys=True),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})},
        },
        "references": [
            {"id": sid, "name": f"panel_{i}", "type": "search"} for i, sid in enumerate(search_ids)
        ],
    }


def build_dashboards(cfg: DetectionConfig) -> dict[str, list[dict[str, Any]]]:
    ssrf_hosts = " or ".join(f'destination.domain:"{h}"' for h in cfg.ssrf.internal_hostnames) or "destination.domain:*"
    specs = {
        "bola_enumeration": [
            ("appsec-bola-events", "BOLA: API requests with resource ids",
             "event.dataset:appsec.api and appsec.resource_id:*",
             ["@timestamp", "user.id", "appsec.endpoint_template", "appsec.resource_id", "http.response.status_code", "appsec.authz.cross_tenant", "source.ip"]),
            ("appsec-bola-denied", "BOLA: 403/404 and cross-tenant responses",
             "event.dataset:appsec.api and (http.response.status_code:403 or http.response.status_code:404 or appsec.authz.cross_tenant:true)",
             ["@timestamp", "user.id", "appsec.endpoint_template", "appsec.resource_id", "http.response.status_code", "source.ip"]),
        ],
        "jwt_abuse": [
            ("appsec-jwt-forged", "JWT: alg=none or validation failures",
             "event.dataset:appsec.api and (appsec.jwt.alg:none or event.action:jwt_validation_failed)",
             ["@timestamp", "user.id", "appsec.jwt.alg", "event.action", "http.response.status_code", "source.ip"]),
            ("appsec-jwt-expired", "JWT: expired tokens accepted",
             "event.dataset:appsec.api and appsec.jwt.expired:true and http.response.status_code >= 200 and http.response.status_code < 300",
             ["@timestamp", "user.id", "appsec.jwt.exp", "appsec.endpoint_template", "http.response.status_code", "source.ip"]),
            ("appsec-jwt-jti", "JWT: events carrying a jti",
             "event.dataset:appsec.api and appsec.jwt.jti:*",
             ["@timestamp", "appsec.jwt.jti", "appsec.client_pair", "source.ip", "source.geo.country_iso_code", "user_agent.original"]),
        ],
        "ssrf_egress": [
            ("appsec-ssrf-egress", "SSRF: egress events",
             "event.dataset:appsec.egress",
             ["@timestamp", "destination.address", "destination.ip", "destination.domain", "http.response.status_code", "error.type", "user.id", "appsec.endpoint_template"]),
            ("appsec-ssrf-internal", "SSRF: egress to internal hostnames",
             f"event.dataset:appsec.egress and ({ssrf_hosts})",
             ["@timestamp", "destination.address", "destination.domain", "url.full", "user.id", "source.ip"]),
        ],
    }
    out: dict[str, list[dict[str, Any]]] = {}
    for scenario, searches in specs.items():
        objs: list[dict[str, Any]] = [_index_pattern()]
        ids = []
        for sid, title, q, cols in searches:
            objs.append(_search(sid, title, q, cols))
            ids.append(sid)
        objs.append(_dashboard(f"appsec-dashboard-{scenario.replace('_', '-')}", f"AppSec {scenario}", ids))
        out[scenario] = objs
    return out


# ----------------------------------------------------------------------- main
def generate(cfg: DetectionConfig | None = None) -> dict[Path, str]:
    cfg = cfg or DetectionConfig.load()
    monitors = {"bola_enumeration": build_bola(cfg), "jwt_abuse": build_jwt(cfg), "ssrf_egress": build_ssrf(cfg)}
    outputs: dict[Path, str] = {}
    for name, mon in monitors.items():
        outputs[MONITORS_DIR / f"{name}.json"] = json.dumps(mon, indent=2, sort_keys=True) + "\n"
    for name, objs in build_dashboards(cfg).items():
        outputs[DASHBOARDS_DIR / f"{name}.ndjson"] = _ndjson(objs)
    return outputs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = ap.parse_args(argv)
    outputs = generate()
    if args.check:
        stale = [str(p) for p, t in outputs.items() if not p.exists() or p.read_text() != t]
        if stale:
            print("stale generated files: " + ", ".join(stale), file=sys.stderr)
            return 1
        return 0
    MONITORS_DIR.mkdir(parents=True, exist_ok=True)
    DASHBOARDS_DIR.mkdir(parents=True, exist_ok=True)
    for path, text in outputs.items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
