"""Properties 16 and 17: baseline plan invariants and retry policy.

Property 16 **Validates: Requirements 5.1, 5.3, 5.6, 5.7**
Property 17 **Validates: Requirements 5.2**

Known limit: "every user sends at least one request" only holds when
``duration * rate >= 12`` (one login slot per user), so that clause is only
asserted for such parameter combinations.
"""
import argparse
import collections
import json
from unittest import mock

import httpx
from hypothesis import given, settings, strategies as st

from app.seed import FIRST_INVOICE_ID, INVOICES_PER_TENANT, TENANT_IDS
from simulators import common, traffic_baseline as tb

USERS = tb.build_users()
N_USERS = len(USERS)

seeds = st.integers(0, 2**32 - 1)
# Bounded so a plan stays small; includes plans below and above the 12-slot limit.
plan_params = st.tuples(st.integers(1, 300), st.integers(1, 20))
full_params = plan_params.filter(lambda p: p[0] * p[1] >= N_USERS)


def _plan(duration, rate, seed):
    return list(tb.plan_requests(USERS, duration, rate, seed))


def _tenant_of_invoice(path):
    inv = int(path.rsplit("/", 1)[1])
    return TENANT_IDS[(inv - FIRST_INVOICE_ID) // INVOICES_PER_TENANT]


def test_user_topology():
    assert N_USERS >= 10
    by_tenant = collections.Counter(u.tenant_id for u in USERS)
    assert len(by_tenant) >= 3 and min(by_tenant.values()) >= 2
    by_ip = collections.defaultdict(set)
    for u in USERS:
        by_ip[u.source_ip].add(u.username)
    assert len(by_ip) >= 2
    assert max(len(v) for v in by_ip.values()) >= 3
    assert all(ip.startswith("192.0.2.") for ip in by_ip)


@settings(max_examples=60, deadline=None)
@given(p=plan_params, seed=seeds)
def test_plan_invoices_are_own_tenant_and_within_duration(p, seed):
    duration, rate = p
    plan = _plan(duration, rate, seed)
    offsets = [r.offset for r in plan]
    assert offsets == sorted(offsets)
    for r in plan:
        assert 0 <= r.offset < duration
        if r.kind == "invoice":
            assert _tenant_of_invoice(r.path) == USERS[r.user_index].tenant_id  # 0% cross-tenant
        else:
            assert r.kind == "login" and r.attempt == 0


@settings(max_examples=60, deadline=None)
@given(p=full_params, seed=seeds)
def test_every_user_sends_at_least_one_request(p, seed):
    duration, rate = p
    assert duration * rate >= 12
    plan = _plan(duration, rate, seed)
    assert {r.user_index for r in plan} == set(range(N_USERS))
    logins = [r.user_index for r in plan if r.kind == "login"]
    assert sorted(logins) == list(range(N_USERS))


@settings(max_examples=60, deadline=None)
@given(p=plan_params, seed=seeds)
def test_plan_is_deterministic_per_seed(p, seed):
    assert _plan(*p, seed) == _plan(*p, seed)


@settings(max_examples=60, deadline=None)
@given(p=plan_params, seed=seeds)
def test_retry_policy(p, seed):
    duration, rate = p
    plan = _plan(duration, rate, seed)
    groups = collections.defaultdict(list)
    for r in plan:
        groups[r.request_id].append(r)
    for rid, reqs in groups.items():
        reqs.sort(key=lambda r: r.attempt)
        orig, retries = reqs[0], reqs[1:]
        assert orig.attempt == 0
        assert len(retries) <= tb.MAX_RETRIES == 3
        assert [r.attempt for r in retries] == list(range(1, len(retries) + 1))
        prev = orig
        for r in retries:
            # same trace id (grouped by it), same user/path; delay 1-30 s after previous attempt
            assert (r.user_index, r.path, r.kind) == (orig.user_index, orig.path, orig.kind)
            delay = r.offset - prev.offset
            assert 1.0 - 1e-9 <= delay <= 30.0 + 1e-9
            assert r.offset < duration
            prev = r


def test_retry_constants():
    assert tb.MAX_RETRIES == 3
    assert tb.RETRY_DELAY_RANGE == (1.0, 30.0)


@settings(max_examples=15, deadline=None)
@given(p=st.tuples(st.integers(1, 20), st.integers(1, 5)), seed=seeds)
def test_every_sent_request_is_labelled_baseline(p, seed, tmp_path_factory):
    duration, rate = p
    ledger = common.Ledger(tmp_path_factory.mktemp("ledger") / "ledger.jsonl")
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(200, json={})

    real = common.SimClient

    def factory(*a, **kw):
        return real(*a, ledger=ledger, **kw)

    args = argparse.Namespace(duration=duration, rate=rate, mode="low-and-slow",
                              target="http://localhost:8080", seed=seed)
    # Virtual clock: sleeping advances time, so the run is instantaneous.
    now = [0.0]

    def sleep(s):
        now[0] += s

    with mock.patch.object(common.safety, "validate_target"), \
            mock.patch.object(tb.common, "SimClient", factory):
        rc = tb.run(args, transport=httpx.MockTransport(handler),
                    clock=lambda: now[0], sleep=sleep)
    assert rc == 0
    assert seen
    for req in seen:
        assert req.headers[common.HEADER_LABEL] == "baseline"
        assert req.headers["x-request-id"]
    # sanity: ledger never receives anything but JSON lines
    for line in ledger.path.read_text().splitlines():
        json.loads(line)
