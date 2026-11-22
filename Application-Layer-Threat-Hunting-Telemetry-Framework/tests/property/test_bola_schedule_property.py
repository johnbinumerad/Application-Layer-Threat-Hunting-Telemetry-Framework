"""Property 18: BOLA schedule.

**Validates: Requirements 6.1, 6.2, 6.6**
"""
import json

import httpx
from hypothesis import given, settings, strategies as st

from labcommon import params, schedule
from simulators import hunt_01_bola_enum as bola
from simulators.common import Ledger, SimClient, GroundTruth

# Rates >= 1/60 rps: below that a single request in a 60 s window already exceeds
# count/60 <= rate, which no schedule can avoid (see report notes).
rates = st.one_of(
    st.floats(min_value=1 / 60, max_value=1000, allow_nan=False, allow_infinity=False),
    st.sampled_from([0.5, 1, 2, 10, 50]),
)
counts = st.integers(min_value=0, max_value=400)


def _window_counts(offsets, window=60.0 - 1e-9):
    # 1 ns tolerance: schedule.py pads the spacing but not the 60 s back-reference, so
    # float conversion can leave a gap of 59.99999999999999 s (sub-ns; reported separately).
    lo = 0
    for hi, t in enumerate(offsets):
        while t - offsets[lo] >= window:
            lo += 1
        yield hi - lo + 1


@settings(max_examples=150, deadline=None)
@given(count=counts, rate=rates)
def test_every_rolling_window_within_rate(count, rate):
    offsets = schedule.request_offsets(count, rate)
    assert len(offsets) == count
    assert offsets == sorted(offsets)
    for n in _window_counts(offsets):
        assert n / 60 <= rate * (1 + 1e-9)
    # Total average: intervals elapsed per second never exceeds rate (N requests span
    # N-1 gaps; the first request at t=0 opens the span).
    if count > 1:
        assert (count - 1) / offsets[-1] <= rate * (1 + 1e-9)


@settings(max_examples=100, deadline=None)
@given(
    start=st.integers(min_value=1, max_value=2**31 - 1000),
    count=st.integers(min_value=1, max_value=40),
    rate=st.floats(min_value=1, max_value=1000, allow_nan=False),
)
def test_request_sequence_user_and_ground_truth(tmp_path_factory, start, count, rate):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json={"tenant_id": "tnt_002"})

    ledger = Ledger(tmp_path_factory.mktemp("ledger") / "ledger.jsonl")
    gt = GroundTruth(label="attack", scenario=bola.SCENARIO, technique=bola.TECHNIQUE)
    p = params.BolaParams(mode="low-and-slow", rate=rate, start_id=start, count=count)
    with SimClient("http://127.0.0.1:8080", gt, ledger=ledger,
                   transport=httpx.MockTransport(handler)) as client:
        summary = bola.run_bola_enum(client, p, "user1@tnt001.example", "pw",
                                     sleep=lambda s: None)

    logins = [r for r in seen if r.url.path == "/api/v1/auth/login"]
    gets = [r for r in seen if r.url.path != "/api/v1/auth/login"]
    assert len(logins) == 1 and summary.requests_sent == count
    ids = [int(r.url.path.rsplit("/", 1)[1]) for r in gets]
    assert ids == list(range(start, start + count))
    assert {r.headers["authorization"] for r in gets} == {"Bearer tok"}  # one user
    for r in seen:
        assert r.headers["x-lab-label"] == "attack"
        assert r.headers["x-lab-scenario"] == "bola"
    assert json.loads(logins[0].content)["username"] == "user1@tnt001.example"
