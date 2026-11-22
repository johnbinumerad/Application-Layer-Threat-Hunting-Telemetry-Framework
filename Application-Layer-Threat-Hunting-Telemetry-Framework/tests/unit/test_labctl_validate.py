"""Unit tests for ``labctl validate`` (pure parts and orchestration failure path)."""

from __future__ import annotations

import json

from labcommon.orchestrator import RunOutcome
from tools.labctl import validate as v


class FakeClient:
    """Empty SIEM: every search returns no hits, alerts API returns the given alerts."""

    def __init__(self, alerts=None):
        self.alerts = alerts or []

    def request(self, method, target, path, *, json=None, params=None, files=None):
        if "/alerts" in path:
            return 200, {"alerts": self.alerts}
        return 200, {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}


def test_replace_time_range_rewrites_every_timestamp_range():
    q = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-5m"}}}, {"term": {"a": 1}}]}}
    out = v.replace_time_range(q, "A", "B")
    assert out["bool"]["filter"][0]["range"]["@timestamp"] == {"gte": "A", "lte": "B"}
    assert q["bool"]["filter"][0]["range"]["@timestamp"] == {"gte": "now-5m"}  # input untouched


def test_anchor_offset_aligns_window_to_first_event():
    assert v.anchor_offset_seconds(1_000_000.7, 600) == 1_000_000 % 600


def test_live_alert_checks():
    intervals = {"baseline": (0, 100), "bola": (100, 200), "jwt": (200, 300), "ssrf": (300, 400)}
    names = {s: v.load_monitor_name(s) for s in v.SCENARIOS}
    alerts = [{"monitor_name": names[s], "start_ms": (intervals[s][0] + 10) * 1000} for s in v.SCENARIOS]
    res = v.evaluate_live_alerts(alerts, intervals)
    assert all(r["ok"] for r in res["scenarios"].values())
    assert res["baseline"] == {"ok": True, "alerts": 0}  # alerts inside attack spans are not baseline FPs
    stray = alerts + [{"monitor_name": names["bola"], "start_ms": 50_000}]
    assert v.evaluate_live_alerts(stray, intervals)["baseline"]["ok"] is False
    assert v.evaluate_live_alerts([], intervals)["scenarios"]["bola"]["ok"] is False


def test_run_validate_stops_on_failure_and_writes_report(tmp_path):
    ran: list[str] = []

    def runner(component, timeout):
        ran.append(component)
        return RunOutcome(1 if component == "bola" else 0)

    clock = iter(range(1_000, 10_000))
    code, report = v.run_validate(FakeClient(), runner, seed=7, wall=lambda: float(next(clock)),
                                  sleep=lambda s: None, reports_dir=tmp_path, ingest_wait=0)
    assert code == 1
    assert ran == ["baseline", "bola"]
    assert report["orchestration"]["failed_component"] == "bola"
    written = json.loads((tmp_path / f"validation-{report['run_id']}.json").read_text())
    assert written["detections"]["bola"]["precision"] == "not applicable"
    assert "bola" in v.format_table(report)
