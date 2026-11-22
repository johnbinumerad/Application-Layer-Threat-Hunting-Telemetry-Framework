"""Subprocess runner that executes a notebook's code cells against a fake SIEM.

Usage: ``python _notebook_runner.py <notebook.ipynb> <populated|empty|down|down_raises|search_fails>``

The fake OpenSearch client is injected by replacing ``lab_common._make_client``
(the only place the real client is built), so ``lab_common.connect()`` /
``run_query()`` run unmodified. Code cells are exec'd in one shared namespace in
order, with an IPython-like ``display`` builtin; plotly ``Figure.show`` is
captured instead of opening a renderer. A JSON report is printed on the last
stdout line, prefixed with ``@@REPORT@@``.
"""
from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
import sys
import traceback

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODE = sys.argv[2]


def _ts(minute: int) -> str:
    return f"2025-01-01T10:{minute:02d}:00.000Z"


def _jti_hits():
    rows = []
    # jti-A is replayed from two IPs / ASNs (the hijack signature); jti-B from one.
    for i, (ip, ua, asn, org, cc) in enumerate([
        ("198.51.100.10", "ua-1", 64497, "Lab ISP B", "DE"),
        ("203.0.113.10", "ua-2", 64498, "Lab ISP C", "BR"),
        ("198.51.100.10", "ua-1", 64497, "Lab ISP B", "DE"),
    ]):
        rows.append({"@timestamp": _ts(i), "appsec.jwt.jti": "jti-A", "appsec.jwt.alg": "HS256",
                     "user.id": "u1", "source.ip": ip, "user_agent.original": ua,
                     "source.as.number": asn, "source.as.organization.name": org,
                     "source.geo.country_iso_code": cc, "http.response.status_code": 200,
                     "appsec.endpoint_template": "/api/v1/invoices/{id}"})
    rows.append({"@timestamp": _ts(5), "appsec.jwt.jti": "jti-B", "appsec.jwt.alg": "HS256",
                 "user.id": "u2", "source.ip": "192.0.2.5", "user_agent.original": "ua-3",
                 "source.as.number": 64496, "source.as.organization.name": "Lab ISP A",
                 "source.geo.country_iso_code": "US", "http.response.status_code": 200,
                 "appsec.endpoint_template": "/api/v1/invoices/{id}"})
    return rows


def _algnone_hits():
    return [{"@timestamp": _ts(m), "appsec.jwt.jti": f"jn-{m}", "appsec.jwt.alg": "none",
             "user.id": "admin", "source.ip": "198.51.100.10", "http.response.status_code": 200,
             "appsec.endpoint_template": "/api/v1/admin/audit"} for m in (1, 1, 3)]


def _expired_hits():
    return [
        {"@timestamp": _ts(2), "appsec.jwt.jti": "je-1", "appsec.jwt.expired": True, "user.id": "u1",
         "source.ip": "192.0.2.7", "http.response.status_code": 200},
        {"@timestamp": _ts(4), "appsec.jwt.jti": "je-2", "appsec.jwt.expired": True, "user.id": "u2",
         "source.ip": "192.0.2.8", "http.response.status_code": 401},
    ]


def _api_hits():
    return [{"@timestamp": _ts(m), "trace.id": f"t-{m}", "user.id": "u1", "source.ip": "198.51.100.77",
             "http.response.status_code": 200} for m in range(4)]


def _egress_hits():
    urls = [("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
            ("http://2130706433:8001/internal/secret", "127.0.0.1"),
            ("http://0177.0.0.1:8001/internal/secret", "127.0.0.1"),
            ("http://[::ffff:127.0.0.1]:8001/internal/secret", "127.0.0.1")]
    rows = [{"@timestamp": _ts(i), "trace.id": f"t-{i}", "url.full": u, "destination.ip": ip,
             "destination.port": 8001, "event.outcome": "success"} for i, (u, ip) in enumerate(urls)]
    rows.append({"@timestamp": _ts(9), "trace.id": "t-ext", "url.full": "http://example.com/x",
                 "destination.ip": "93.184.216.34", "destination.port": 80, "event.outcome": "success"})
    return rows


def _hits(rows):
    return {"hits": {"total": {"value": len(rows)}, "hits": [{"_source": r} for r in rows]}}


class FakeOpenSearch:
    """Minimal stand-in for ``opensearchpy.OpenSearch`` driven by the query body."""

    def __init__(self, mode: str):
        self.mode = mode
        self.searches: list = []

    def ping(self, **_kw):
        if self.mode == "down":
            return False
        if self.mode == "down_raises":
            raise ConnectionError("simulated: connection refused")
        return True

    def search(self, index=None, body=None, **_kw):
        self.searches.append(body)
        if self.mode == "search_fails":
            raise RuntimeError("simulated search failure")
        if self.mode == "empty":
            return {"hits": {"total": {"value": 0}, "hits": []}}
        text = json.dumps(body)
        aggs = body.get("aggs", {})
        if "bucket" in aggs:  # notebook 01 cardinality
            return {"hits": {"hits": []}, "aggregations": {"bucket": {"buckets": [
                {"key": 1735725600000, "key_as_string": _ts(m), "doc_count": 40, "user": {"buckets": [
                    {"key": "u-attacker", "doc_count": 40, "endpoint": {"buckets": [
                        {"key": "/api/v1/invoices/{id}", "doc_count": 40,
                         "distinct_ids": {"value": 10 * (m + 1)}}]}}]}}
                for m in (0, 10, 20)]}}}
        if "user" in aggs:  # notebook 01 response-class ratio
            return {"hits": {"hits": []}, "aggregations": {"user": {"buckets": [
                {"key": k, "doc_count": 20, "status_class": {"buckets": {
                    "2xx": {"doc_count": a}, "3xx": {"doc_count": 0},
                    "4xx": {"doc_count": b}, "5xx": {"doc_count": 0}}}}
                for k, a, b in (("u-attacker", 4, 16), ("u-normal", 20, 0))]}}}
        if "appsec.jwt.jti" in text and "exists" in text:
            return _hits(_jti_hits())
        if '"appsec.jwt.alg": "none"' in text:
            return _hits(_algnone_hits())
        if "appsec.jwt.expired" in text:
            return _hits(_expired_hits())
        if '"appsec.egress"' in text:
            return _hits(_egress_hits())
        if '"appsec.api"' in text:
            return _hits(_api_hits())
        raise AssertionError(f"unexpected query in fake SIEM: {text}")


def main() -> None:
    nb_path = os.path.join(REPO, sys.argv[1]) if not os.path.isabs(sys.argv[1]) else sys.argv[1]
    os.chdir(REPO)  # the image's work dir holds config/ next to the notebooks
    sys.path[:0] = [os.path.join(REPO, "notebooks"), REPO]

    import lab_common  # noqa: E402
    import plotly.graph_objects as go  # noqa: E402

    fake = FakeOpenSearch(MODE)
    lab_common._make_client = lambda: fake  # inject fake client

    displays: list = []
    figures: list = []

    def display(obj=None, *_a, **_k):
        displays.append(type(obj).__name__)

    def show(self, *_a, **_k):
        figures.append(self.layout.title.text or "")

    go.Figure.show = show
    builtins.display = display

    with open(nb_path, encoding="utf-8") as fh:
        nb = json.load(fh)

    ns: dict = {"__name__": "__main__"}
    cell_errors: list = []
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        for idx, cell in enumerate(nb["cells"]):
            if cell["cell_type"] != "code":
                continue
            try:
                exec(compile("".join(cell["source"]), f"<cell {idx}>", "exec"), ns)
            except BaseException:  # noqa: BLE001 - report every failure
                cell_errors.append({"cell": idx, "traceback": traceback.format_exc()})
    report = {
        "errors": cell_errors,
        "stdout": out.getvalue(),
        "displays": displays,
        "figures": figures,
        "searches": len(fake.searches),
        "siem_up": lab_common.SIEM_UP,
    }
    print("@@REPORT@@" + json.dumps(report))


if __name__ == "__main__":
    main()
