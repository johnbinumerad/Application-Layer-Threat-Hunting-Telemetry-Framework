"""``labctl cleanup``: remove everything the lab generated (Req 13.6, 13.7).

Steps: ``delete_by_query`` on every document carrying
``lab.ground_truth.run_id`` (pre-existing documents are never matched), delete
the generated alerts, verify zero generated items remain, then clear the local
token ledger. If anything cannot be removed, the remaining items are listed and
the exit code is non-zero (the ledger is kept so ``verify-no-secrets`` still
works). The whole run is bounded by a 5 minute budget.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tools.labctl.setup import Client, HttpClient

ROOT = Path(__file__).resolve().parent.parent.parent
LEDGER_PATH = ROOT / ".lab" / "ledger.jsonl"

TELEMETRY_INDEX = "appsec-telemetry-*"
ALERT_INDEX = ".opendistro-alerting-alerts,.opendistro-alerting-alert-history-*"
GROUND_TRUTH_QUERY: dict[str, Any] = {"exists": {"field": "lab.ground_truth.run_id"}}
ALL_QUERY: dict[str, Any] = {"match_all": {}}
BUDGET_S = 300.0
MAX_LISTED = 100

# (label, index expression, query) for each class of generated item.
TARGETS: list[tuple[str, str, dict[str, Any]]] = [
    ("telemetry", TELEMETRY_INDEX, GROUND_TRUTH_QUERY),
    ("alert", ALERT_INDEX, ALL_QUERY),
]

_PARAMS = {"ignore_unavailable": "true", "allow_no_indices": "true"}


def _delete(client: Client, index: str, query: dict) -> str | None:
    """delete_by_query; return an error string or None."""
    s, b = client.request(
        "POST", "opensearch", f"/{index}/_delete_by_query",
        json={"query": query},
        params={**_PARAMS, "refresh": "true", "conflicts": "proceed", "wait_for_completion": "true"},
    )
    if s == 404:  # nothing to delete
        return None
    if not 200 <= s < 300:
        return f"HTTP {s}: {str(b)[:200]}"
    if isinstance(b, dict) and b.get("failures"):
        return f"{len(b['failures'])} delete failure(s)"
    return None


def _remaining(client: Client, index: str, query: dict) -> tuple[list[str], str | None]:
    """Return (ids of remaining docs as ``index/id``, error or None)."""
    s, b = client.request(
        "POST", "opensearch", f"/{index}/_search",
        json={"query": query, "size": MAX_LISTED, "_source": False, "track_total_hits": True},
        params=_PARAMS,
    )
    if s == 404:
        return [], None
    if not 200 <= s < 300:
        return [], f"verification search failed: HTTP {s}: {str(b)[:200]}"
    hits = b["hits"]["hits"]
    items = [f"{h['_index']}/{h['_id']}" for h in hits]
    total = b["hits"]["total"]
    total = total["value"] if isinstance(total, dict) else total
    if total > len(items):
        items.append(f"... and {total - len(items)} more")
    return items, None


def run_cleanup(
    client: Client,
    ledger_path: Path | str = LEDGER_PATH,
    budget_s: float = BUDGET_S,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[int, list[str]]:
    """Return ``(exit_code, remaining_items)``."""
    deadline = clock() + budget_s
    remaining: list[str] = []
    for label, index, query in TARGETS:
        if clock() > deadline:
            remaining.append(f"{label}: not processed (5 minute budget exceeded)")
            continue
        err = None
        try:
            err = _delete(client, index, query)
        except Exception as exc:  # noqa: BLE001 - verification below reports what is left
            err = str(exc)
        if err:
            print(f"cleanup: {label} deletion problem: {err}", file=sys.stderr)
        try:
            items, verr = _remaining(client, index, query)
        except Exception as exc:  # noqa: BLE001
            items, verr = [], f"verification search failed: {exc}"
        remaining += [f"{label}: {i}" for i in items]
        if verr:
            remaining.append(f"{label}: {verr}")
        elif err and not items:
            # Delete reported an error but verification shows zero left: fine.
            pass
    if clock() > deadline:
        remaining.append("cleanup exceeded the 5 minute budget")
    if remaining:
        return 1, remaining
    path = Path(ledger_path)
    try:
        if path.exists():
            path.write_text("", encoding="utf-8")
    except OSError as exc:
        return 1, [f"ledger: {path}: {exc}"]
    return 0, []


def main(argv: list[str] | None = None) -> int:
    client = HttpClient()
    try:
        client._http.timeout = BUDGET_S  # long-running delete_by_query  # noqa: SLF001
    except AttributeError:
        pass
    code, remaining = run_cleanup(client)
    if code:
        print(f"cleanup: FAILED, {len(remaining)} item(s) remain:", file=sys.stderr)
        for item in remaining:
            print(f"  {item}", file=sys.stderr)
        return 1
    print("cleanup: complete (0 generated documents or alerts remain; ledger cleared)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
