"""Property 20: JWT abuse plan.

Feature: application-layer-threat-hunting-framework, Property 20: JWT abuse plan

Runs the real JWT_Simulator technique functions through a real ``SimClient`` whose HTTP
transport is an in-memory recorder, then inspects the requests that would have been sent.

**Validates: Requirements 7.1, 7.2, 7.3**
"""
import base64
import json
import tempfile
import time
from pathlib import Path

import httpx
from hypothesis import HealthCheck, given, settings, strategies as st

from app import auth
from labcommon.enrich import load_table
from simulators import hunt_02_jwt_abuse as jwt_sim
from simulators.common import GroundTruth, Ledger, SimClient

USER = {"id": "usr_001", "tenant_id": "tnt_001", "role": "user", "username": "user01@tnt001.lab"}
counts = st.integers(min_value=1, max_value=40)
hijack_counts = st.integers(min_value=2, max_value=40)
modes = st.sampled_from(["noisy", "low-and-slow"])


def _seg(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


class _Recorder:
    def __init__(self):
        self.sent = []  # (wall_time, monotonic, headers)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.sent.append((time.time(), time.monotonic(), dict(request.headers)))
        return httpx.Response(200, json={})


def _client(rec, tmp):
    return SimClient(
        "http://127.0.0.1:8080", GroundTruth(label="attack", scenario="jwt"),
        ledger=Ledger(Path(tmp) / "ledger.jsonl"),
        resolver=lambda host, port: ["127.0.0.1"],
        transport=httpx.MockTransport(rec),
    )


def _token(headers):
    return headers["authorization"].removeprefix("Bearer ")


def _pace_for(mode):
    return jwt_sim._pacer(mode, lambda _s: None)


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(count=counts, mode=modes)
def test_alg_none_tokens_have_none_header_and_empty_signature(count, mode):
    rec = _Recorder()
    with tempfile.TemporaryDirectory() as tmp, _client(rec, tmp) as client:
        jwt_sim.run_alg_none(client, count, jwt_sim.JwtAbuseReport(), _pace_for(mode), USER)
    assert len(rec.sent) == count
    for _, _, h in rec.sent:
        parts = _token(h).split(".")
        assert len(parts) == 3
        assert _seg(parts[0])["alg"] == "none"
        assert parts[2] == ""


@settings(max_examples=50, deadline=None)
@given(count=counts, mode=modes)
def test_replay_tokens_expired_at_least_60s_before_send(count, mode):
    rec = _Recorder()
    with tempfile.TemporaryDirectory() as tmp, _client(rec, tmp) as client:
        jwt_sim.run_expired_replay(client, count, jwt_sim.JwtAbuseReport(), _pace_for(mode), USER)
    assert len(rec.sent) == count
    for wall, _, h in rec.sent:
        claims = _seg(_token(h).split(".")[1])
        assert claims["exp"] <= wall - 60


@settings(max_examples=50, deadline=None)
@given(count=hijack_counts)
def test_hijack_single_jti_distinct_asns_within_60s(count):
    table = load_table()
    rec = _Recorder()
    slept = []
    with tempfile.TemporaryDirectory() as tmp, _client(rec, tmp) as client:
        jwt_sim.run_hijack(client, count, jwt_sim.JwtAbuseReport(), USER, slept.append)
    assert len(rec.sent) == count
    jtis = {_seg(_token(h).split(".")[1])["jti"] for _, _, h in rec.sent}
    assert len(jtis) == 1
    ips = {h["x-forwarded-for"] for _, _, h in rec.sent}
    assert len(ips) >= 2
    asns = {table.lookup(ip).asn for ip in ips}
    assert len(asns) >= 2
    # Window: the simulated schedule (sum of requested sleeps) plus real elapsed time.
    elapsed = rec.sent[-1][1] - rec.sent[0][1]
    assert sum(slept) + elapsed <= 60
