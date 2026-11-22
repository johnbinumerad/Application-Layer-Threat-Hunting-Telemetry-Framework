"""Notebook execution tests (task 11.6) against a fake OpenSearch client.

**Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.7, 12.8**

No SIEM or Docker is needed: each notebook's code cells are exec'd by
``_notebook_runner.py`` in a subprocess with a fake client injected into
``notebooks/lab_common.py``. The subprocess interpreter must have the notebook
image's pinned deps (pandas, plotly, pyyaml, opensearch-py, jinja2). Point
``LAB_NOTEBOOK_PYTHON`` at such an interpreter (e.g. a venv built from
``notebooks/Dockerfile``'s pins); otherwise the current interpreter is used, and
the tests skip when it lacks those packages.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUNNER = Path(__file__).with_name("_notebook_runner.py")
PYTHON = os.environ.get("LAB_NOTEBOOK_PYTHON", sys.executable)
TIMEOUT_S = 300  # Req 12.7

NOTEBOOKS = {
    "bola": "notebooks/01_detecting_bola_via_cardinality.ipynb",
    "jwt": "notebooks/02_anomalous_session_and_jwt_hunting.ipynb",
    "ssrf": "notebooks/03_ssrf_egress_by_trace_id.ipynb",
}
# Scenario names the notebooks pass to lab.run_query (used in the empty-result message).
SCENARIOS = {
    "bola": ["BOLA resource-id cardinality", "BOLA response-class ratio"],
    "jwt": ["JWT JTI usage", "JWT alg=none", "expired JWT"],
    "ssrf": ["SSRF egress (inbound)", "SSRF egress (egress)"],
}
# Minimum charts / tables a populated run must produce (Req 12.1-12.5).
MIN_FIGURES = {"bola": 2, "jwt": 3, "ssrf": 2}
MIN_DISPLAYS = {"bola": 2, "jwt": 4, "ssrf": 3}
FIGURE_TITLES = {
    "bola": ["Distinct Resource_ID per user per endpoint template", "2xx/3xx/4xx/5xx ratio per user identity"],
    "jwt": ["Distinct source IPs per JTI", "alg=none requests per minute", "Expired-token requests per user"],
    "ssrf": ["Egress events by destination class", "Alternate-encoding SSRF payloads"],
}


def _deps_available() -> bool:
    probe = "import pandas, plotly, yaml, opensearchpy, jinja2"
    try:
        return subprocess.run([PYTHON, "-c", probe], capture_output=True, timeout=60).returncode == 0
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _deps_available(),
    reason="interpreter lacks notebook deps (pandas/plotly/pyyaml/opensearch-py/jinja2); "
           "set LAB_NOTEBOOK_PYTHON to a venv built from notebooks/Dockerfile pins",
)


def run_notebook(key: str, mode: str) -> dict:
    start = time.monotonic()
    proc = subprocess.run(
        [PYTHON, str(RUNNER), NOTEBOOKS[key], mode],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, f"runner crashed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in reversed(proc.stdout.splitlines()) if l.startswith("@@REPORT@@"))
    report = json.loads(line[len("@@REPORT@@"):])
    report["elapsed"] = elapsed
    return report


def _assert_no_errors(report: dict) -> None:
    assert report["errors"] == [], "\n".join(e["traceback"] for e in report["errors"])


@pytest.mark.parametrize("key", NOTEBOOKS)
def test_populated_siem_runs_without_errors_and_produces_outputs(key):
    report = run_notebook(key, "populated")
    _assert_no_errors(report)
    assert report["siem_up"] is True
    assert "SIEM unreachable" not in report["stdout"]
    assert "No matching data" not in report["stdout"]
    assert report["elapsed"] < TIMEOUT_S
    assert report["searches"] >= 1
    assert len(report["figures"]) >= MIN_FIGURES[key]
    assert len(report["displays"]) >= MIN_DISPLAYS[key]
    for expected in FIGURE_TITLES[key]:
        assert any(expected in t for t in report["figures"]), (expected, report["figures"])


def test_ssrf_populated_highlights_private_destinations_and_encodings():
    report = run_notebook("ssrf", "populated")
    _assert_no_errors(report)
    assert "Styler" in report["displays"]  # private-range highlighting rendered (Req 12.5)


@pytest.mark.parametrize("mode", ["down", "down_raises"])
@pytest.mark.parametrize("key", NOTEBOOKS)
def test_siem_unreachable_prints_message_and_skips_dependent_cells(key, mode):
    report = run_notebook(key, mode)
    _assert_no_errors(report)
    assert report["siem_up"] is False
    assert "SIEM unreachable" in report["stdout"]
    assert report["searches"] == 0
    assert report["displays"] == []
    assert report["figures"] == []
    assert "No matching data" not in report["stdout"]


@pytest.mark.parametrize("key", NOTEBOOKS)
def test_empty_results_print_no_matching_data_without_exceptions(key):
    report = run_notebook(key, "empty")
    _assert_no_errors(report)
    assert report["siem_up"] is True
    assert report["figures"] == []
    assert report["displays"] == []
    messages = re.findall(r"^No matching data for (.+) in (.+)$", report["stdout"], re.M)
    assert messages, report["stdout"]
    for scenario, time_range in messages:
        assert scenario and time_range
    printed = {s for s, _ in messages}
    assert printed & set(SCENARIOS[key])


@pytest.mark.parametrize("key", NOTEBOOKS)
def test_query_failure_is_reported_as_no_matching_data(key):
    report = run_notebook(key, "search_fails")
    _assert_no_errors(report)
    assert "No matching data for" in report["stdout"]
    assert report["figures"] == []


@pytest.mark.skip(reason="Live SIEM test: requires the running Docker Compose lab (OpenSearch on "
                         "127.0.0.1:9200) with simulators run; no SIEM/Docker is available in this "
                         "environment. Run `jupyter nbconvert --execute` against the lab manually.")
@pytest.mark.integration
@pytest.mark.parametrize("key", NOTEBOOKS)
def test_live_siem_notebooks_execute_within_300s(key):  # pragma: no cover
    raise AssertionError("skipped")
