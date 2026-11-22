"""``labctl validate [--seed N]``: measure detection quality (Req 11.4, 11.5, 13.1-13.5).

Flow:
  1. Run baseline -> BOLA -> JWT -> SSRF via ``labcommon.orchestrator`` (one at a time,
     30 min cap each); record wall-clock start/end per component.
  2. Wait up to 30 s for ingestion to settle.
  3. Re-execute each stored monitor query (``opensearch/monitors/*.json``) over the run
     range. BOLA uses tumbling windows anchored to the first ground-truth event
     (``offset``), so counts are reproducible (D16). Alerted events are mapped back to
     ground-truth labels and scored with ``labcommon.metrics`` (TP/FP/FN/precision).
  4. Poll the live Alerting API: >= 1 alert per scenario within 5 min of the attack
     finishing, and zero alerts during baseline + 5 min (alerts that start while an
     attack component is running are attributed to that attack, not the baseline).
  5. Write ``reports/validation-<run_id>.json`` and print a table.

Exit status: 0 only if the run completed and both live-alert checks hold; 1 otherwise.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from labcommon import metrics as lab_metrics
from labcommon import orchestrator
from labcommon.schema import DetectionConfig

ROOT = Path(__file__).resolve().parent.parent.parent
MONITORS_DIR = ROOT / "opensearch" / "monitors"
REPORTS_DIR = ROOT / "reports"
INDEX = "appsec-telemetry-*"

INGEST_WAIT_S = 30.0
LIVE_ALERT_WINDOW_S = 300.0
SCENARIOS = ("bola", "jwt", "ssrf")
MONITOR_FILES = {"bola": "bola_enumeration.json", "jwt": "jwt_abuse.json", "ssrf": "ssrf_egress.json"}
DATASET = {"bola": "appsec.api", "jwt": "appsec.api", "ssrf": "appsec.egress"}
GT_LABEL = "lab.ground_truth.label"
GT_SCENARIO = "lab.ground_truth.scenario"
GT_ROLE = "lab.ground_truth.role"
PAGE = 1000


# ------------------------------------------------------------------ helpers
def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_field(src: Mapping[str, Any], dotted: str) -> Any:
    """Read a field from a flat-keyed or nested ``_source``."""
    if dotted in src:
        return src[dotted]
    cur: Any = src
    for part in dotted.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur


def replace_time_range(node: Any, gte: str, lte: str) -> Any:
    """Return a copy of a query with every ``@timestamp`` range replaced by [gte, lte]."""
    node = copy.deepcopy(node)

    def walk(n: Any) -> None:
        if isinstance(n, dict):
            rng = n.get("range")
            if isinstance(rng, dict) and "@timestamp" in rng:
                rng["@timestamp"] = {"gte": gte, "lte": lte}
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)

    walk(node)
    return node


def _search(client: Any, body: dict[str, Any]) -> dict[str, Any]:
    status, resp = client.request("POST", "opensearch", f"/{INDEX}/_search", json=body)
    if status == 404:
        return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}
    if not 200 <= status < 300:
        raise RuntimeError(f"search failed: HTTP {status}: {str(resp)[:300]}")
    return resp


def search_all(client: Any, query: dict[str, Any], source: list[str]) -> list[dict[str, Any]]:
    """All matching ``_source`` docs, paged with search_after on (@timestamp, event.id)."""
    out: list[dict[str, Any]] = []
    after: list[Any] | None = None
    while True:
        body: dict[str, Any] = {
            "size": PAGE, "query": query, "_source": source,
            "sort": [{"@timestamp": "asc"}, {"event.id": "asc"}],
        }
        if after:
            body["search_after"] = after
        hits = _search(client, body)["hits"]["hits"]
        out.extend(h.get("_source", {}) for h in hits)
        if len(hits) < PAGE:
            return out
        after = hits[-1].get("sort")
        if not after:
            return out


def count_ground_truth(client: Any, gte: str, lte: str) -> int:
    body = {"size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": [{"exists": {"field": GT_LABEL}},
                                          {"range": {"@timestamp": {"gte": gte, "lte": lte}}}]}}}
    return int(_search(client, body)["hits"]["total"]["value"])


def wait_for_ingestion(
    client: Any, gte: str, lte: str, timeout: float = INGEST_WAIT_S, interval: float = 2.0,
    sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
) -> int:
    """Wait up to ``timeout`` s for the ground-truth event count to be non-zero and stable."""
    deadline = clock() + timeout
    last = -1
    while True:
        try:
            n = count_ground_truth(client, gte, lte)
        except Exception:  # noqa: BLE001 - SIEM may still be settling
            n = -1
        if n > 0 and n == last:
            return n
        last = n
        if clock() >= deadline:
            return max(n, 0)
        sleep(interval)


def load_monitor(scenario: str, monitors_dir: Path = MONITORS_DIR) -> dict[str, Any]:
    return json.loads((monitors_dir / MONITOR_FILES[scenario]).read_text())


def monitor_query(monitor: dict[str, Any]) -> dict[str, Any]:
    return monitor["inputs"][0]["search"]["query"]


def ids_of(docs: Iterable[Mapping[str, Any]]) -> set[str]:
    found = (get_field(d, "event.id") for d in docs)
    return {str(i) for i in found if i is not None}


# ------------------------------------------------------------ re-execution
def anchor_offset_seconds(first_event_ts: float, window_s: int) -> int:
    """Offset that makes a tumbling window start exactly at the first ground-truth event."""
    return int(first_event_ts) % window_s


def first_ground_truth_ts(client: Any, gte: str, lte: str) -> float | None:
    docs = _search(client, {
        "size": 1, "sort": [{"@timestamp": "asc"}], "_source": ["@timestamp"],
        "query": {"bool": {"filter": [{"exists": {"field": GT_LABEL}},
                                      {"range": {"@timestamp": {"gte": gte, "lte": lte}}}]}},
    })["hits"]["hits"]
    if not docs:
        return None
    value = get_field(docs[0].get("_source", {}), "@timestamp")
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value / 1000.0
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def alerted_bola(client: Any, monitor: dict, cfg: DetectionConfig, gte: str, lte: str, offset_s: int) -> set[str]:
    b = cfg.bola
    window_s = b.window_minutes * 60
    q = replace_time_range(monitor_query(monitor), gte, lte)
    comp = q["aggregations"]["composite_agg"]
    for src in comp["composite"]["sources"]:
        hist = src.get("window", {}).get("date_histogram")
        if hist:
            hist["offset"] = f"{offset_s}s"
    base_filter = q["query"]["bool"]
    alerted: set[str] = set()
    after: dict | None = None
    while True:
        comp["composite"].pop("after", None)
        if after:
            comp["composite"]["after"] = after
        agg = _search(client, q).get("aggregations", {}).get("composite_agg", {})
        for bucket in agg.get("buckets", []):
            total = bucket["doc_count"]
            distinct = bucket["distinct_ids"]["value"]
            bad = bucket["c403"]["doc_count"] + bucket["c404"]["doc_count"] + bucket["c_xtenant"]["doc_count"]
            if (distinct > b.distinct_ids_threshold and distinct > b.retry_suppression_max_ids
                    and total > 0 and bad / total > b.error_ratio_threshold):
                key = bucket["key"]
                start_ms = int(key["window"])
                docs = search_all(client, {"bool": {
                    "filter": [*base_filter["filter"][:1],
                               {"term": {"user.id": key["user"]}},
                               {"term": {"appsec.endpoint_template": key["endpoint"]}},
                               {"range": {"@timestamp": {"gte": start_ms, "lt": start_ms + window_s * 1000,
                                                         "format": "epoch_millis"}}}],
                    "must_not": base_filter.get("must_not", [])}}, ["event.id"])
                alerted |= ids_of(docs)
        after = agg.get("after_key")
        if not after or not agg.get("buckets"):
            return alerted


def alerted_jwt(client: Any, monitor: dict, gte: str, lte: str) -> set[str]:
    q = replace_time_range(monitor_query(monitor), gte, lte)
    base = q["query"]
    aggs = _search(client, {**q, "size": 0}).get("aggregations", {})
    alerted: set[str] = set()
    for name in ("forged_or_failed", "expired_accepted"):
        flt = q["aggregations"][name]["filter"]
        docs = search_all(client, {"bool": {"filter": [base, flt]}}, ["event.id"])
        alerted |= ids_of(docs)
    jtis = [b["key"] for b in aggs.get("jti_reuse", {}).get("buckets", [])
            if b.get("client_pairs", {}).get("value", 0) > 1]
    for i in range(0, len(jtis), 500):
        docs = search_all(client, {"bool": {"filter": [base, {"terms": {"appsec.jwt.jti": jtis[i:i + 500]}}]}},
                          ["event.id"])
        alerted |= ids_of(docs)
    return alerted


def alerted_ssrf(client: Any, monitor: dict, gte: str, lte: str) -> set[str]:
    q = replace_time_range(monitor_query(monitor), gte, lte)
    return ids_of(search_all(client, q["query"], ["event.id"]))


def score_detections(
    client: Any, gte: str, lte: str, cfg: DetectionConfig | None = None,
    monitors_dir: Path = MONITORS_DIR,
) -> dict[str, dict[str, Any]]:
    """TP/FP/FN/precision per detection over the run range."""
    cfg = cfg or DetectionConfig.load()
    first = first_ground_truth_ts(client, gte, lte)
    offset_s = anchor_offset_seconds(first, cfg.bola.window_minutes * 60) if first is not None else 0
    out: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        monitor = load_monitor(scenario, monitors_dir)
        if scenario == "bola":
            alerted = alerted_bola(client, monitor, cfg, gte, lte, offset_s)
        elif scenario == "jwt":
            alerted = alerted_jwt(client, monitor, gte, lte)
        else:
            alerted = alerted_ssrf(client, monitor, gte, lte)
        docs = search_all(client, {"bool": {"filter": [
            {"term": {"event.dataset": DATASET[scenario]}},
            {"exists": {"field": GT_LABEL}},
            {"range": {"@timestamp": {"gte": gte, "lte": lte}}}]}},
            ["event.id", GT_LABEL, GT_SCENARIO, GT_ROLE])
        events = []
        for d in docs:
            label, scn = get_field(d, GT_LABEL), get_field(d, GT_SCENARIO)
            if label == "attack" and scn != scenario:
                continue  # another scenario's attack traffic is not this detection's ground truth
            events.append({"event_id": str(get_field(d, "event.id")), "label": label,
                           "role": get_field(d, GT_ROLE)})
        m = lab_metrics.compute_metrics(events, alerted)
        out[scenario] = {**m.as_dict(), "alerted_events": len(alerted), "ground_truth_events": len(events)}
    return out


# --------------------------------------------------------------- live alerts
def fetch_live_alerts(client: Any) -> list[dict[str, Any]]:
    """All alerts known to the Alerting plugin as ``{monitor_name, start_ms}``."""
    status, body = client.request("GET", "opensearch", "/_plugins/_alerting/monitors/alerts",
                                  params={"size": "1000"})
    if not 200 <= status < 300 or not isinstance(body, dict):
        raise RuntimeError(f"alerting API: HTTP {status}")
    return [{"monitor_name": a.get("monitor_name"), "start_ms": a.get("start_time")}
            for a in body.get("alerts", []) if a.get("start_time") is not None]


def evaluate_live_alerts(
    alerts: list[dict[str, Any]], intervals: Mapping[str, tuple[float, float]],
    window_s: float = LIVE_ALERT_WINDOW_S,
) -> dict[str, Any]:
    """Pure check of Req 11.4/11.5 over wall-clock intervals ``{component: (start, end)}``."""
    by_monitor: dict[str, list[float]] = {}
    for a in alerts:
        by_monitor.setdefault(str(a["monitor_name"]), []).append(a["start_ms"] / 1000.0)
    attack_spans = [intervals[c] for c in SCENARIOS if c in intervals]
    result: dict[str, Any] = {"scenarios": {}, "baseline": None}
    for scenario in SCENARIOS:
        if scenario not in intervals:
            result["scenarios"][scenario] = {"ok": False, "alerts": 0, "reason": "scenario did not run"}
            continue
        start, end = intervals[scenario]
        name = load_monitor_name(scenario)
        n = sum(1 for t in by_monitor.get(name, []) if start <= t <= end + window_s)
        result["scenarios"][scenario] = {"ok": n >= 1, "alerts": n}
    if "baseline" in intervals:
        bs, be = intervals["baseline"]
        stray = [t for ts in by_monitor.values() for t in ts
                 if bs <= t <= be + window_s and not any(s <= t <= e for s, e in attack_spans)]
        result["baseline"] = {"ok": not stray, "alerts": len(stray)}
    else:
        result["baseline"] = {"ok": False, "alerts": 0, "reason": "baseline did not run"}
    return result


def load_monitor_name(scenario: str) -> str:
    return load_monitor(scenario)["name"]


def poll_live_alerts(
    client: Any, intervals: Mapping[str, tuple[float, float]],
    sleep: Callable[[float], None] = time.sleep, wall: Callable[[], float] = time.time,
    interval: float = 15.0,
) -> dict[str, Any]:
    """Poll until every scenario has an alert or its 5-minute deadline passes."""
    while True:
        res = evaluate_live_alerts(fetch_live_alerts(client), intervals)
        pending = [s for s, r in res["scenarios"].items()
                   if not r["ok"] and s in intervals and wall() < intervals[s][1] + LIVE_ALERT_WINDOW_S]
        if not pending:
            return res
        sleep(interval)


# ------------------------------------------------------------------- report
def format_table(report: Mapping[str, Any]) -> str:
    rows = [("detection", "TP", "FP", "FN", "precision %", "live alert", "")]
    live = report.get("live_alerts") or {}
    for s in SCENARIOS:
        d = report.get("detections", {}).get(s)
        if not d:
            continue
        lv = (live.get("scenarios") or {}).get(s, {})
        rows.append((s, str(d["tp"]), str(d["fp"]), str(d["fn"]), str(d["precision"]),
                     "yes" if lv.get("ok") else "NO", ""))
    widths = [max(len(r[i]) for r in rows) for i in range(6)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r[:6], widths)).rstrip() for r in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    b = live.get("baseline")
    if b is not None:
        lines.append(f"baseline live alerts: {b['alerts']} ({'ok' if b['ok'] else 'FAIL'})")
    return "\n".join(lines)


def write_report(report: Mapping[str, Any], reports_dir: Path = REPORTS_DIR) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"validation-{report['run_id']}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return path


def run_validate(
    client: Any, base_runner: orchestrator.Runner, seed: int | None = None,
    wall: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
    reports_dir: Path = REPORTS_DIR, cfg: DetectionConfig | None = None,
    ingest_wait: float = INGEST_WAIT_S, poll: bool = True,
) -> tuple[int, dict[str, Any]]:
    run_id = uuid.uuid4().hex
    intervals: dict[str, tuple[float, float]] = {}

    def timed(component: str, timeout_s: float) -> orchestrator.RunOutcome:
        start = wall()
        try:
            return base_runner(component, timeout_s)
        finally:
            intervals[component] = (start, wall())

    started = wall()
    result = orchestrator.run_validation(timed)
    report: dict[str, Any] = {
        "run_id": run_id, "seed": seed, "started": iso(started),
        "components": [{"component": r.component, "exit_code": r.exit_code, "timed_out": r.timed_out,
                        "duration_s": round(r.duration_s, 3),
                        "start": iso(intervals[r.component][0]) if r.component in intervals else None,
                        "end": iso(intervals[r.component][1]) if r.component in intervals else None}
                       for r in result.results],
        "orchestration": {"success": result.success, "failed_component": result.failed_component,
                          "failure_reason": result.failure_reason},
    }
    print(orchestrator.format_failure(result), file=sys.stderr if not result.success else sys.stdout)
    gte, rng_end = iso(started - 1), None
    ok = result.success
    try:
        rng_end = iso(wall() + 60)
        wait_for_ingestion(client, gte, rng_end, ingest_wait, sleep=sleep)
        rng_end = iso(wall() + 1)
        report["range"] = {"gte": gte, "lte": rng_end}
        report["detections"] = score_detections(client, gte, rng_end, cfg)
        if result.success and poll:
            report["live_alerts"] = poll_live_alerts(client, intervals, sleep=sleep, wall=wall)
            live = report["live_alerts"]
            ok = ok and all(r["ok"] for r in live["scenarios"].values()) and live["baseline"]["ok"]
        elif not result.success:
            ok = False
    except Exception as exc:  # noqa: BLE001 - report SIEM failures, keep partial report
        report["error"] = str(exc)
        print(f"validate: error: {exc}", file=sys.stderr)
        ok = False
    report["ended"] = iso(wall())
    report["passed"] = ok
    path = write_report(report, reports_dir)
    print(format_table(report))
    print(f"report: {path}")
    return (0 if ok else 1), report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labctl validate", description="Run the full detection validation")
    p.add_argument("--seed", type=int, default=None, help="deterministic seed passed to every simulator")
    p.add_argument("--baseline-duration", default="60", help="baseline duration in seconds (default 60)")
    p.add_argument("--baseline-rate", default="5", help="baseline requests/s (default 5)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from tools.labctl.setup import HttpClient

    seed_args = ["--seed", str(args.seed)] if args.seed is not None else []
    runner = orchestrator.subprocess_runner({
        "baseline": ["--duration", str(args.baseline_duration), "--rate", str(args.baseline_rate), *seed_args],
        "bola": seed_args, "jwt": seed_args, "ssrf": seed_args,
    })
    code, _ = run_validate(HttpClient(), runner, seed=args.seed)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
