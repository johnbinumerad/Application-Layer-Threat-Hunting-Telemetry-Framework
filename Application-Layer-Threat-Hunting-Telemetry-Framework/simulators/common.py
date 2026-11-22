"""Shared simulator client (Req 5.7, 6.6, 9.1-9.3, 4.4).

Targets only the validated gateway, adds X-Forwarded-For for simulated source IPs,
adds X-Lab-* ground-truth headers, and records issued raw tokens/passwords in the
gitignored .lab/ledger.jsonl.
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import httpx

from labcommon import params, safety

DEFAULT_TARGET = "http://127.0.0.1:8080"
DEFAULT_SEED = 0
LEDGER_PATH = Path(__file__).resolve().parent.parent / ".lab" / "ledger.jsonl"
DEFAULT_TIMEOUT_S = 10.0

LABELS = ("baseline", "attack")
HEADER_LABEL = "X-Lab-Label"
HEADER_SCENARIO = "X-Lab-Scenario"
HEADER_TECHNIQUE = "X-Lab-Technique"
HEADER_RUN_ID = "X-Lab-Run-Id"
HEADER_ROLE = "X-Lab-Role"


def add_common_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Add the shared --mode, --target and --seed options."""
    parser.add_argument("--mode", choices=params.MODES, default=params.DEFAULT_MODE,
                        help="pacing/rate preset (explicit parameters override it)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="gateway base URL")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="deterministic seed")
    return parser


def new_run_id() -> str:
    return uuid.uuid4().hex


class Ledger:
    """Append-only JSONL record of raw secrets issued during a run (local only)."""

    def __init__(self, path: Path | str = LEDGER_PATH):
        self.path = Path(path)

    def record(self, kind: str, run_id: str, **fields: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.time(), "kind": kind, "run_id": run_id, **fields}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


@dataclass(frozen=True)
class GroundTruth:
    label: str
    scenario: str
    technique: str | None = None
    role: str | None = None

    def __post_init__(self) -> None:
        if self.label not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")


class SimClient:
    """HTTP client bound to a validated gateway target."""

    def __init__(
        self,
        target: str,
        ground_truth: GroundTruth,
        run_id: str | None = None,
        ledger: Ledger | None = None,
        gateway: safety.GatewayConfig | None = None,
        resolver: safety.Resolver = safety.system_resolver,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        sleep: Callable[[float], None] = time.sleep,
    ):
        # Validate before any request can be made; exits 2 with a stderr message.
        safety.validate_target(target, gateway, resolver)
        self.target = target.rstrip("/")
        self.ground_truth = ground_truth
        self.run_id = run_id or new_run_id()
        self.ledger = ledger or Ledger()
        self.sleep = sleep
        self._http = httpx.Client(base_url=self.target, timeout=timeout,
                                  transport=transport, follow_redirects=False)

    def ground_truth_headers(self, technique: str | None = None, role: str | None = None) -> dict[str, str]:
        gt = self.ground_truth
        h = {HEADER_LABEL: gt.label, HEADER_SCENARIO: gt.scenario, HEADER_RUN_ID: self.run_id}
        tech = technique or gt.technique
        if tech:
            h[HEADER_TECHNIQUE] = tech
        r = role or gt.role
        if r:
            h[HEADER_ROLE] = r
        return h

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        source_ip: str | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        technique: str | None = None,
        role: str | None = None,
    ) -> httpx.Response:
        """Send one request to the gateway. `path` must be a path, not a URL."""
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        h = self.ground_truth_headers(technique, role)
        if source_ip:
            h["X-Forwarded-For"] = source_ip
        if token:
            h["Authorization"] = f"Bearer {token}"
        if headers:
            h.update(headers)
        return self._http.request(method, path, headers=h, json=json_body)

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("POST", path, **kw)

    def login(self, username: str, password: str, source_ip: str | None = None,
              **kw: Any) -> str | None:
        """Log in; ledger the raw password and issued token. Returns the token or None."""
        self.ledger.record("password", self.run_id, username=username, password=password)
        resp = self.post("/api/v1/auth/login", json_body={"username": username, "password": password},
                         source_ip=source_ip, **kw)
        if resp.status_code != 200:
            return None
        try:
            token = resp.json().get("access_token") or resp.json().get("token")
        except ValueError:
            return None
        if token:
            self.record_token(token, username=username)
        return token

    def record_token(self, token: str, **fields: Any) -> None:
        """Ledger a raw token that this run issued or forged."""
        self.ledger.record("token", self.run_id, token=token, **fields)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SimClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
