"""Property 33: Setup loader (fake OpenSearch client).

**Validates: Requirements 11.3, 11.6**
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from tools.labctl import setup as S

names = st.text(alphabet="abcdefghij", min_size=1, max_size=6)


class FakeClient:
    """In-memory OpenSearch/Dashboards keyed by name/id; can fail chosen names."""

    def __init__(self, fail_names: frozenset[str] = frozenset()):
        self.pipelines: dict[str, dict] = {}
        self.templates: dict[str, dict] = {}
        self.dashboards: dict[str, bytes] = {}
        self.monitors: dict[str, dict] = {}  # id -> body
        self.fail_names = fail_names
        self._next = 0

    def request(self, method, target, path, *, json=None, params=None, files=None):
        if method == "PUT" and path.startswith("/_ingest/pipeline/"):
            self.pipelines[path.rsplit("/", 1)[1]] = json
            return 200, {"acknowledged": True}
        if method == "PUT" and path.startswith("/_index_template/"):
            self.templates[path.rsplit("/", 1)[1]] = json
            return 200, {"acknowledged": True}
        if path == "/api/saved_objects/_import":
            assert params == {"overwrite": "true"}
            fname, data, _ = files["file"]
            if fname in self.fail_names:
                return 500, {"error": "boom"}
            self.dashboards[fname] = data  # overwrite=true => keyed upsert
            return 200, {"success": True}
        if path.endswith("/monitors/_search"):
            n = json["query"]["match_phrase"]["monitor.name"]
            hits = [{"_id": i, "_source": b} for i, b in self.monitors.items() if b["name"] == n]
            return 200, {"hits": {"hits": hits}}
        if method == "POST" and path == "/_plugins/_alerting/monitors":
            if json["name"] in self.fail_names:
                return 500, {"error": "boom"}
            self._next += 1
            self.monitors[f"id{self._next}"] = json
            return 201, {}
        if method == "PUT" and path.startswith("/_plugins/_alerting/monitors/"):
            self.monitors[path.rsplit("/", 1)[1]] = json
            return 200, {}
        raise AssertionError(f"unexpected {method} {path}")


def _make_dir(tmp: Path, dash: list[str], mons: list[str]):
    (tmp / "p.json").write_text("{}")
    (tmp / "t.json").write_text("{}")
    (tmp / "d").mkdir()
    (tmp / "m").mkdir()
    for n in dash:
        (tmp / "d" / f"{n}.ndjson").write_text("{}\n")
    for n in mons:
        (tmp / "m" / f"{n}.json").write_text(json.dumps({"name": n, "enabled": True}))
    return S.collect_artifacts(tmp / "p.json", tmp / "t.json", tmp / "d", tmp / "m")


@settings(max_examples=50, deadline=None)
@given(
    flags=st.lists(st.booleans(), min_size=0, max_size=12),
)
def test_all_attempted_failures_logged_and_nonzero_iff_failed(flags):
    attempted: list[str] = []
    arts = []
    for i, fails in enumerate(flags):
        def load(c, i=i, fails=fails):
            attempted.append(f"a{i}")
            if fails:
                raise RuntimeError(f"err-{i}")
        arts.append(S.Artifact(f"a{i}", load))
    logs: list[str] = []
    failures = S.run_setup(object(), arts, log=logs.append)
    assert attempted == [f"a{i}" for i in range(len(flags))]
    expected = [i for i, f in enumerate(flags) if f]
    assert [n for n, _ in failures] == [f"a{i}" for i in expected]
    for i in expected:
        assert any(f"a{i}" in m and f"err-{i}" in m for m in logs)
    assert len(logs) == len(expected)
    assert bool(failures) == any(flags)


@settings(max_examples=30, deadline=None)
@given(
    dash=st.sets(names, max_size=4),
    mons=st.sets(names, max_size=4),
    data=st.data(),
    runs=st.integers(min_value=1, max_value=4),
)
def test_real_loaders_failures_attempt_all_and_idempotent(dash, mons, data, runs):
    failing = frozenset(
        data.draw(st.sets(st.sampled_from(sorted([f"{n}.ndjson" for n in dash] + sorted(mons))), max_size=3))
        if (dash or mons) else []
    )
    with tempfile.TemporaryDirectory() as td:
        arts = _make_dir(Path(td), sorted(dash), sorted(mons))
        client = FakeClient(failing)
        results = [S.run_setup(client, arts, log=lambda m: None) for _ in range(runs)]
        failed_names = {n for n, _ in results[0]}
        expected = {f"dashboard:{n}.ndjson" for n in dash if f"{n}.ndjson" in failing} | {
            f"monitor:{n}.json" for n in mons if n in failing
        }
        assert failed_names == expected
        assert all({n for n, _ in r} == expected for r in results)
        # Everything not failing was loaded; no duplicates after N runs
        assert set(client.dashboards) == {f"{n}.ndjson" for n in dash} - failing
        mon_names = [b["name"] for b in client.monitors.values()]
        assert len(mon_names) == len(set(mon_names))
        assert set(mon_names) == set(mons) - failing
        assert set(client.templates) == {S.TEMPLATE_NAME}
        assert set(client.pipelines) == {S.PIPELINE_NAME}


def test_main_exit_code(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(S, "HttpClient", lambda: fake)
    monkeypatch.setattr(S, "wait_healthy", lambda c: True)
    monkeypatch.setattr(S, "collect_artifacts", lambda: [S.Artifact("x", lambda c: (_ for _ in ()).throw(RuntimeError("e")))])
    assert S.main([]) == 1
    monkeypatch.setattr(S, "collect_artifacts", lambda: [S.Artifact("x", lambda c: None)])
    assert S.main([]) == 0
