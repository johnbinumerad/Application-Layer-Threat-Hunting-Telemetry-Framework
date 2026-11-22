"""BOLA_Simulator: low-and-slow BOLA/IDOR enumeration (Req 6.1-6.6).

Authenticates as a single seeded user, then requests invoice ids
``start, start + 1, ...`` from a fixed non-tenant source IP (``198.51.100.77``),
honoring a schedule that keeps the average request rate at or below ``--rate``
over any rolling 60 s window. Requests are labelled ``attack``/``bola`` so
analysts can separate them from baseline traffic in ground-truth records.

``--mode low-and-slow`` (default) uses a 0.5 rps preset; ``--mode noisy`` raises
the default rate preset. An explicit ``--rate`` always overrides the preset and
is always enforced as the schedule's cap (Req 6.2).
"""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Callable

from app.seed import TENANT_IDS, lab_password, seed_users_spec
from labcommon import params, schedule
from simulators.common import GroundTruth, SimClient, add_common_args

SOURCE_IP = "198.51.100.77"
DEFAULT_START_ID = 1011
DEFAULT_COUNT = 80
SCENARIO = "bola"
TECHNIQUE = "idor_enumeration"


def _bola_user() -> dict:
    """The single seeded user the simulator authenticates as (tnt_001's first user)."""
    return next(u for u in seed_users_spec() if u["tenant_id"] == TENANT_IDS[0])


@dataclass(frozen=True)
class BolaSummary:
    requests_sent: int = 0
    cross_tenant_successes: int = 0
    non_success: int = 0

    def print(self, out=sys.stdout) -> None:
        print(f"requests_sent={self.requests_sent} "
              f"cross_tenant_successes={self.cross_tenant_successes} "
              f"non_success={self.non_success}", file=out)


def run_bola_enum(
    client: SimClient,
    bola_params: params.BolaParams,
    username: str,
    password: str,
    sleep: Callable[[float], None] = time.sleep,
) -> BolaSummary:
    """Authenticate once, then enumerate ``count`` invoice ids per the schedule."""
    token = client.login(username, password, source_ip=SOURCE_IP)
    if not token:
        print("error: bola simulator could not authenticate", file=sys.stderr)
        return BolaSummary()

    my_tenant = username.split("@", 1)[1].split(".", 1)[0]  # e.g. "tnt001"
    my_tenant_id = my_tenant[:3] + "_" + my_tenant[3:]

    offsets = schedule.request_offsets(bola_params.count, bola_params.rate)
    sent = 0
    cross_tenant_successes = 0
    non_success = 0
    start = time.monotonic()
    for i, offset in enumerate(offsets):
        invoice_id = bola_params.start_id + i
        target_t = start + offset
        delay = target_t - time.monotonic()
        if delay > 0:
            sleep(delay)
        resp = client.get(f"/api/v1/invoices/{invoice_id}", token=token, source_ip=SOURCE_IP,
                          technique=TECHNIQUE)
        sent += 1
        if 200 <= resp.status_code < 300:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            resource_tenant = body.get("tenant_id")
            if resource_tenant is not None and resource_tenant != my_tenant_id:
                cross_tenant_successes += 1
        else:
            non_success += 1
    return BolaSummary(sent, cross_tenant_successes, non_success)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BOLA/IDOR enumeration simulator")
    add_common_args(parser)
    parser.add_argument("--rate", type=float, default=None,
                        help="requests per second cap, average over any rolling 60s window "
                             "(overrides the --mode preset)")
    parser.add_argument("--start-id", type=int, default=None,
                        help=f"first invoice id to request (default {DEFAULT_START_ID})")
    parser.add_argument("--count", type=int, default=None,
                        help="number of requests to send (overrides the --mode preset)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        bola_params = params.resolve_bola(vars(args), default_start_id=DEFAULT_START_ID)
    except params.ParamError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    user = _bola_user()
    n = int(user["id"].split("_")[1])
    password = lab_password(n)
    ground_truth = GroundTruth(label="attack", scenario=SCENARIO, technique=TECHNIQUE)
    with SimClient(args.target, ground_truth) as client:
        summary = run_bola_enum(client, bola_params, user["username"], password)
    summary.print()
    return 0


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
