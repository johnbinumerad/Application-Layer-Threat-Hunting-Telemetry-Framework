"""Property 34: Cleanup.

**Validates: Requirements 13.6, 13.7**

A fake in-memory OpenSearch client holds a mix of generated (ground-truth
marked) telemetry documents, generated alerts and pre-existing documents.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from tools.labctl.cleanup import run_cleanup

TELEMETRY_INDEXES = ["appsec-telemetry-2024.01.01", "appsec-telemetry-2024.01.02"]
ALERT_INDEXES = [".opendistro-alerting-alerts", ".opendistro-alerting-alert-history-000001"]
OTHER_INDEXES = ["unrelated-index", "appsec-other"]


class FakeClient:
    """Index -> {id: doc}; supports only what cleanup uses."""

    def __init__(self, docs: dict[str, dict[str, dict]], undeletable: set[tuple[str, str]]):
        self.docs = {i: dict(d) for i, d in docs.items()}
        self.undeletable = undeletable

    @staticmethod
    def _match(query: dict, doc: dict) -> bool:
        if "match_all" in query:
            return True
        field = query["exists"]["field"]
        return field == "lab.ground_truth.run_id" and "run_id" in doc.get("ground_truth", {})

    def _indexes(self, expr: str) -> list[str]:
        out: list[str] = []
        for pat in expr.split(","):
            if pat.endswith("*"):
                out += [i for i in self.docs if i.startswith(pat[:-1])]
            elif pat in self.docs:
                out.append(pat)
        return out

    def request(self, method, target, path, *, json=None, params=None, files=None):
        assert target == "opensearch" and method == "POST"
        expr, op = path.lstrip("/").split("/", 1)
        indexes = self._indexes(expr)
        query = json["query"]
        if op == "_delete_by_query":
            deleted = 0
            for i in indexes:
                for did in list(self.docs[i]):
                    if self._match(query, self.docs[i][did]) and (i, did) not in self.undeletable:
                        del self.docs[i][did]
                        deleted += 1
            return 200, {"deleted": deleted, "failures": []}
        assert op == "_search"
        hits = [
            {"_index": i, "_id": did}
            for i in indexes
            for did, d in self.docs[i].items()
            if self._match(query, d)
        ]
        return 200, {"hits": {"total": {"value": len(hits)}, "hits": hits[: json["size"]]}}


GEN = {"ground_truth": {"run_id": "r1"}}
PRE: dict = {}

doc_kind = st.sampled_from(["gen_tel", "pre_tel", "alert", "other"])


@st.composite
def stores(draw):
    n = draw(st.integers(0, 15))
    docs: dict[str, dict[str, dict]] = {i: {} for i in TELEMETRY_INDEXES + ALERT_INDEXES + OTHER_INDEXES}
    kinds: dict[tuple[str, str], str] = {}
    for n_i in range(n):
        kind = draw(doc_kind)
        pool = {
            "gen_tel": TELEMETRY_INDEXES, "pre_tel": TELEMETRY_INDEXES,
            "alert": ALERT_INDEXES, "other": OTHER_INDEXES,
        }[kind]
        idx = draw(st.sampled_from(pool))
        did = f"d{n_i}"
        docs[idx][did] = GEN if kind == "gen_tel" else PRE
        kinds[(idx, did)] = kind
    return docs, kinds


def _run(docs, undeletable):
    client = FakeClient(docs, undeletable)
    with tempfile.TemporaryDirectory() as td:
        ledger = Path(td) / "ledger.jsonl"
        ledger.write_text('{"token": "x"}\n', encoding="utf-8")
        code, remaining = run_cleanup(client, ledger)
        content = ledger.read_text(encoding="utf-8")
    return client, code, remaining, content


@settings(max_examples=100, deadline=None)
@given(stores())
def test_cleanup_removes_exactly_generated(store):
    docs, kinds = store
    client, code, remaining, ledger = _run(docs, set())
    assert code == 0 and remaining == []
    assert ledger == ""
    expected = {k for k, v in kinds.items() if v in ("pre_tel", "other")}
    actual = {(i, d) for i, m in client.docs.items() for d in m}
    assert actual == expected


@settings(max_examples=100, deadline=None)
@given(stores(), st.data())
def test_cleanup_reports_exactly_undeletable(store, data):
    docs, kinds = store
    generated = [k for k, v in kinds.items() if v in ("gen_tel", "alert")]
    stuck = set(data.draw(st.lists(st.sampled_from(generated), unique=True))) if generated else set()
    client, code, remaining, ledger = _run(docs, stuck)
    survivors = {(i, d) for i, m in client.docs.items() for d in m}
    assert survivors == stuck | {k for k, v in kinds.items() if v in ("pre_tel", "other")}
    if stuck:
        assert code != 0
        assert sorted(r.split(": ", 1)[1] for r in remaining) == sorted(f"{i}/{d}" for i, d in stuck)
        assert ledger != ""  # ledger kept on failure
    else:
        assert code == 0 and remaining == [] and ledger == ""
