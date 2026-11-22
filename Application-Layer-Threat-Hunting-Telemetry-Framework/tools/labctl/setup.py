"""``labctl setup``: the lab-setup one-shot job (Req 7.4, 11.2, 11.3, 11.6).

Waits for OpenSearch and Dashboards (120 s), then in order: PUT the ingest
pipeline, PUT the index template, POST dashboards with ``overwrite=true``, and
upsert monitors by name. Every artifact is attempted; failures are logged with
the artifact name and error, and the exit code is non-zero if any failed.
All steps are idempotent, so re-runs create no duplicates.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parent.parent.parent
PIPELINE_PATH = ROOT / "infra" / "opensearch" / "ingest_pipeline.json"
TEMPLATE_PATH = ROOT / "infra" / "opensearch" / "index_template.json"
DASHBOARDS_DIR = ROOT / "opensearch" / "dashboards"
MONITORS_DIR = ROOT / "opensearch" / "monitors"

PIPELINE_NAME = "appsec-enrich"
TEMPLATE_NAME = "appsec-telemetry"
WAIT_TIMEOUT_S = 120.0


class Client(Protocol):
    """Minimal HTTP surface so the loader can run against a fake in tests."""

    def request(
        self, method: str, target: str, path: str, *, json: Any = None,
        params: dict[str, str] | None = None, files: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """``target`` is ``"opensearch"`` or ``"dashboards"``. Returns (status, body)."""


class HttpClient:
    def __init__(self, env: dict[str, str] | None = None):
        import httpx

        env = os.environ if env is None else env
        self._bases = {
            "opensearch": f"http://{env.get('OPENSEARCH_HOST', 'localhost')}:{env.get('OPENSEARCH_PORT', '9200')}",
            "dashboards": f"http://{env.get('DASHBOARDS_HOST', 'localhost')}:{env.get('DASHBOARDS_PORT', '5601')}",
        }
        self._http = httpx.Client(timeout=30.0)

    def request(self, method, target, path, *, json=None, params=None, files=None):
        headers = {"osd-xsrf": "true"} if target == "dashboards" else {}
        resp = self._http.request(
            method, self._bases[target] + path, json=json, params=params, files=files, headers=headers
        )
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        return resp.status_code, body


@dataclass
class Artifact:
    name: str
    load: Callable[[Client], None]


def _check(status: int, body: Any, what: str) -> None:
    if not 200 <= status < 300:
        raise RuntimeError(f"{what}: HTTP {status}: {json.dumps(body)[:300] if not isinstance(body, str) else body[:300]}")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _put_pipeline(path: Path) -> Callable[[Client], None]:
    def load(c: Client) -> None:
        s, b = c.request("PUT", "opensearch", f"/_ingest/pipeline/{PIPELINE_NAME}", json=_read_json(path))
        _check(s, b, "PUT ingest pipeline")
    return load


def _put_template(path: Path) -> Callable[[Client], None]:
    def load(c: Client) -> None:
        s, b = c.request("PUT", "opensearch", f"/_index_template/{TEMPLATE_NAME}", json=_read_json(path))
        _check(s, b, "PUT index template")
    return load


def _post_dashboard(path: Path) -> Callable[[Client], None]:
    def load(c: Client) -> None:
        s, b = c.request(
            "POST", "dashboards", "/api/saved_objects/_import",
            params={"overwrite": "true"},
            files={"file": (path.name, path.read_bytes(), "application/ndjson")},
        )
        _check(s, b, "import dashboard")
        if isinstance(b, dict) and b.get("success") is False:
            raise RuntimeError(f"import dashboard: {json.dumps(b.get('errors'))[:300]}")
    return load


def _upsert_monitor(path: Path) -> Callable[[Client], None]:
    def load(c: Client) -> None:
        body = _read_json(path)
        name = body["name"]
        s, found = c.request(
            "POST", "opensearch", "/_plugins/_alerting/monitors/_search",
            json={"size": 100, "query": {"match_phrase": {"monitor.name": name}}},
        )
        # Missing config index (first run) is reported as 404: treat as "none yet".
        hits: list[dict] = []
        if s != 404:
            _check(s, found, "search monitor")
            hits = [h for h in found["hits"]["hits"] if h.get("_source", {}).get("monitor", h.get("_source", {})).get("name") == name]
        if hits:
            s, b = c.request("PUT", "opensearch", f"/_plugins/_alerting/monitors/{hits[0]['_id']}", json=body)
            _check(s, b, "update monitor")
        else:
            s, b = c.request("POST", "opensearch", "/_plugins/_alerting/monitors", json=body)
            _check(s, b, "create monitor")
    return load


def collect_artifacts(
    pipeline: Path = PIPELINE_PATH, template: Path = TEMPLATE_PATH,
    dashboards: Path = DASHBOARDS_DIR, monitors: Path = MONITORS_DIR,
) -> list[Artifact]:
    arts = [
        Artifact(f"ingest-pipeline:{PIPELINE_NAME}", _put_pipeline(pipeline)),
        Artifact(f"index-template:{TEMPLATE_NAME}", _put_template(template)),
    ]
    arts += [Artifact(f"dashboard:{p.name}", _post_dashboard(p)) for p in sorted(dashboards.glob("*.ndjson"))]
    arts += [Artifact(f"monitor:{p.name}", _upsert_monitor(p)) for p in sorted(monitors.glob("*.json"))]
    return arts


def wait_healthy(
    client: Client, timeout: float = WAIT_TIMEOUT_S, *,
    sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
) -> bool:
    deadline = clock() + timeout
    pending = {"opensearch": "/_cluster/health", "dashboards": "/api/status"}
    while True:
        for target, path in list(pending.items()):
            try:
                s, b = client.request("GET", target, path)
                ok = s == 200 and not (target == "opensearch" and isinstance(b, dict) and b.get("status") == "red")
            except Exception:
                ok = False
            if ok:
                del pending[target]
        if not pending:
            return True
        if clock() >= deadline:
            print(f"setup: timed out waiting for: {', '.join(pending)}", file=sys.stderr)
            return False
        sleep(2.0)


def run_setup(client: Client, artifacts: list[Artifact], log: Callable[[str], None] | None = None) -> list[tuple[str, str]]:
    """Attempt every artifact; return ``[(name, error)]`` for the failures."""
    log = log or (lambda m: print(m, file=sys.stderr))
    failures: list[tuple[str, str]] = []
    for art in artifacts:
        try:
            art.load(client)
            print(f"setup: loaded {art.name}")
        except Exception as exc:  # noqa: BLE001 - continue with the rest
            failures.append((art.name, str(exc)))
            log(f"setup: FAILED {art.name}: {exc}")
    return failures


def main(argv: list[str] | None = None) -> int:
    client = HttpClient()
    if not wait_healthy(client):
        return 1
    failures = run_setup(client, collect_artifacts())
    if failures:
        print(f"setup: {len(failures)} artifact(s) failed: {', '.join(n for n, _ in failures)}", file=sys.stderr)
        return 1
    print("setup: complete")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
