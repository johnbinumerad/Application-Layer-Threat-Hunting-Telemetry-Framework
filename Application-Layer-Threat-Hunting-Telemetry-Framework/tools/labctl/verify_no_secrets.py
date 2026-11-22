"""``labctl verify-no-secrets`` (Req 4.4).

Reads the simulators' gitignored ``.lab/ledger.jsonl`` (raw tokens and passwords
issued during simulations) and searches OpenSearch for each one. Any document
containing a raw secret is a failure; the document index and id are named, the
secret itself is never printed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path

LEDGER_PATH = Path(__file__).resolve().parents[2] / ".lab" / "ledger.jsonl"
SECRET_KEYS = ("token", "password")
_QS_SPECIAL = re.compile(r'([+\-=&|><!(){}\[\]^"~*?:\\/ ])')

Search = Callable[[dict], list[dict]]  # body -> list of hits


def load_secrets(path: Path | str = LEDGER_PATH) -> list[str]:
    """Return unique non-empty raw secrets from the ledger (empty if no ledger)."""
    p = Path(path)
    if not p.exists():
        return []
    secrets: dict[str, None] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        for key in SECRET_KEYS:
            val = entry.get(key)
            if isinstance(val, str) and val:
                secrets[val] = None
    return list(secrets)


def build_query(secret: str) -> dict:
    escaped = _QS_SPECIAL.sub(r"\\\1", secret)
    return {
        "size": 20,
        "_source": True,
        "query": {
            "query_string": {
                "query": f"*{escaped}*",
                "fields": ["*"],
                "allow_leading_wildcard": True,
                "analyze_wildcard": True,
                "lenient": True,
            }
        },
    }


def find_leaks(secrets: list[str], search: Search) -> list[dict]:
    """Return ``[{index, id}]`` for documents whose source contains a secret."""
    leaks: dict[tuple[str, str], None] = {}
    for secret in secrets:
        for hit in search(build_query(secret)):
            source = json.dumps(hit.get("_source", {}), ensure_ascii=False)
            # Compare against the raw and JSON-escaped forms to avoid false positives.
            if secret in source or json.dumps(secret)[1:-1] in source:
                leaks[(str(hit.get("_index")), str(hit.get("_id")))] = None
    return [{"index": i, "id": d} for i, d in leaks]


def _http_search(env: dict[str, str] | None = None) -> Search:
    import httpx

    env = os.environ if env is None else env
    base = f"http://{env.get('OPENSEARCH_HOST', 'localhost')}:{env.get('OPENSEARCH_PORT', '9200')}"
    client = httpx.Client(timeout=30.0)

    def search(body: dict) -> list[dict]:
        resp = client.post(f"{base}/_search", json=body, params={"ignore_unavailable": "true"})
        resp.raise_for_status()
        return resp.json().get("hits", {}).get("hits", [])

    return search


def main(argv: list[str] | None = None, *, search: Search | None = None,
         ledger_path: Path | str | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--ledger" and len(args) > 1:
        ledger_path, args = args[1], args[2:]
    secrets = load_secrets(ledger_path or LEDGER_PATH)
    if not secrets:
        print("verify-no-secrets: ledger empty or missing; nothing to check")
        return 0
    try:
        leaks = find_leaks(secrets, search or _http_search())
    except Exception as exc:  # connection/HTTP errors: cannot assert absence
        print(f"verify-no-secrets: OpenSearch query failed: {exc}", file=sys.stderr)
        return 2
    if leaks:
        print(f"verify-no-secrets: FAIL - raw secrets found in {len(leaks)} document(s):", file=sys.stderr)
        for leak in leaks:
            print(f"  index={leak['index']} id={leak['id']}", file=sys.stderr)
        return 1
    print(f"verify-no-secrets: OK - {len(secrets)} secret(s) checked, 0 hits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
