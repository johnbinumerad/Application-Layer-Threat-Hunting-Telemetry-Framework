"""Baseline traffic generator (Req 5.1-5.7).

Simulates normal multi-user traffic: 12 seeded users across 5 tenants log in and then
fetch only invoices owned by their own tenant. Several users share one corporate NAT
source IP, and some requests simulate mobile retry storms (the same ``x-request-id``
re-sent up to 3 times after a 1-30 s delay). Every request is labelled
``lab.ground_truth.label=baseline``.

Usage: python -m simulators.traffic_baseline --duration 300 --rate 2 [--seed N]
"""
from __future__ import annotations

import argparse
import heapq
import random
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterator

import httpx

from labcommon import params
from simulators import common

try:  # seed data is the single source of truth for users/tenants/invoice ids
    from app.seed import (FIRST_INVOICE_ID, INVOICES_PER_TENANT, TENANT_IDS,
                          seed_users_spec)
except Exception:  # pragma: no cover - fallback keeps the simulator host-runnable
    FIRST_INVOICE_ID, INVOICES_PER_TENANT = 1001, 10
    TENANT_IDS = [f"tnt_{i:03d}" for i in range(1, 6)]

    def seed_users_spec() -> list[dict]:
        out, n = [], 0
        for t, count in enumerate([3, 3, 2, 2, 2]):
            for _ in range(count):
                n += 1
                out.append({"id": f"usr_{n:03d}",
                            "username": f"user{n:02d}@{TENANT_IDS[t].replace('_', '')}.lab",
                            "tenant_id": TENANT_IDS[t], "role": "user",
                            "password": f"lab-pass-{n:02d}"})
        return out

SCENARIO = "baseline"
CORPORATE_NAT_IP = "192.0.2.10"
SOURCE_IPS = ("192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13")
NAT_USER_COUNT = 4          # first 4 users share the corporate NAT IP (>= 3 required)
RETRY_PROBABILITY = 0.1
MAX_RETRIES = 3
RETRY_DELAY_RANGE = (1.0, 30.0)


@dataclass(frozen=True)
class BaselineUser:
    username: str
    password: str
    tenant_id: str
    source_ip: str
    invoice_ids: tuple[int, ...]


@dataclass(frozen=True)
class PlannedRequest:
    offset: float          # seconds from run start
    user_index: int
    kind: str              # "login" | "invoice"
    path: str
    request_id: str
    attempt: int = 0       # 0 = original, 1..3 = retry


def build_users() -> list[BaselineUser]:
    users = []
    for i, u in enumerate(seed_users_spec()):
        t = TENANT_IDS.index(u["tenant_id"])
        first = FIRST_INVOICE_ID + t * INVOICES_PER_TENANT
        ip = CORPORATE_NAT_IP if i < NAT_USER_COUNT else SOURCE_IPS[1 + (i % (len(SOURCE_IPS) - 1))]
        users.append(BaselineUser(u["username"], u["password"], u["tenant_id"], ip,
                                  tuple(range(first, first + INVOICES_PER_TENANT))))
    return users


def plan_requests(users: list[BaselineUser], duration: int, rate: int, seed: int
                  ) -> Iterator[PlannedRequest]:
    """Lazily yield the deterministic plan in offset order (all offsets < duration)."""
    rng = random.Random(seed)
    total = duration * rate
    login_order = list(range(len(users)))
    rng.shuffle(login_order)
    pending: list[tuple[float, int, PlannedRequest]] = []
    tie = 0
    for slot in range(total):
        offset = slot / rate
        while pending and pending[0][0] <= offset:
            yield heapq.heappop(pending)[2]
        if slot < len(login_order):
            ui = login_order[slot]
            yield PlannedRequest(offset, ui, "login", "/api/v1/auth/login", uuid.UUID(int=rng.getrandbits(128)).hex)
            continue
        ui = rng.randrange(len(users))
        inv = rng.choice(users[ui].invoice_ids)
        path = f"/api/v1/invoices/{inv}"
        rid = uuid.UUID(int=rng.getrandbits(128)).hex
        yield PlannedRequest(offset, ui, "invoice", path, rid)
        if rng.random() < RETRY_PROBABILITY:  # simulated timeout -> retry storm
            t = offset
            for attempt in range(1, rng.randint(1, MAX_RETRIES) + 1):
                t += rng.uniform(*RETRY_DELAY_RANGE)
                if t >= duration:
                    break
                tie += 1
                heapq.heappush(pending, (t, tie, PlannedRequest(t, ui, "invoice", path, rid, attempt)))
    while pending:  # remaining retries that still fall inside the duration
        yield heapq.heappop(pending)[2]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Baseline (normal) traffic generator")
    p.add_argument("--duration", help="run duration in seconds (1-86400)")
    p.add_argument("--rate", help="requests per second (1-1000)")
    common.add_common_args(p)
    return p


def run(args: argparse.Namespace,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep) -> int:
    # Validate before any request (and before target validation / client creation).
    try:
        bp = params.resolve_baseline({"duration": args.duration, "rate": args.rate})
        params.resolve_mode(args.mode)
    except params.ParamError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    users = build_users()
    gt = common.GroundTruth(label="baseline", scenario=SCENARIO, technique="normal_use", role=None)
    sent = failed = 0
    tokens: dict[int, str | None] = {}
    with common.SimClient(args.target, gt, transport=transport, sleep=sleep) as client:
        start = clock()
        for pr in plan_requests(users, bp.duration, bp.rate, args.seed):
            wait = pr.offset - (clock() - start)
            if wait > 0:
                sleep(wait)
            if clock() - start >= bp.duration:
                break
            u = users[pr.user_index]
            try:
                if pr.kind == "login":
                    tokens[pr.user_index] = client.login(
                        u.username, u.password, source_ip=u.source_ip,
                        headers={"x-request-id": pr.request_id})
                else:
                    resp = client.get(pr.path, token=tokens.get(pr.user_index),
                                      source_ip=u.source_ip,
                                      headers={"x-request-id": pr.request_id})
                    if resp.status_code >= 400:
                        failed += 1
                sent += 1
            except httpx.HTTPError:
                sent += 1
                failed += 1
    print(f"baseline complete: requests sent={sent}, failed={failed}, "
          f"users={len(users)}, seed={args.seed}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
