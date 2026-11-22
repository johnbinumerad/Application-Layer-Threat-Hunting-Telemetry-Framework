"""Property 19: Simulator summaries.

Feature: application-layer-threat-hunting-framework, Property 19: Simulator summaries

Runs the real simulator run loops against in-memory fake clients and compares the
summaries with an independent classification of the simulated responses.

**Validates: Requirements 6.4, 7.8, 7.9, 8.5**
"""
import io
import re

import httpx
from hypothesis import given, settings, strategies as st

from labcommon import params
from simulators import hunt_01_bola_enum as bola
from simulators import hunt_02_jwt_abuse as jwt_sim
from simulators import hunt_03_ssrf_egress as ssrf

USERNAME = "user01@tnt001.lab"
MY_TENANT = "tnt_001"
USER = {"id": "usr_001", "tenant_id": MY_TENANT, "role": "user", "username": USERNAME}


class _Resp:
    def __init__(self, status_code, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


# ---------------------------------------------------------------- BOLA

bola_responses = st.one_of(
    st.tuples(st.integers(200, 299), st.sampled_from([MY_TENANT, "tnt_002", "tnt_003", None]))
    .map(lambda t: (t[0], {} if t[1] is None else {"tenant_id": t[1]})),
    st.tuples(st.integers(200, 299), st.just("bad")).map(lambda t: (t[0], None)),  # non-JSON 2xx
    st.tuples(st.sampled_from([301, 400, 401, 403, 404, 429, 500, 503]),
              st.sampled_from([{}, {"tenant_id": "tnt_002"}])),
)


class _BolaClient:
    def __init__(self, responses):
        self._it = iter(responses)

    def login(self, username, password, source_ip=None):
        return "tok"

    def get(self, path, token=None, source_ip=None, technique=None):
        status, body = next(self._it)
        return _Resp(status, body)


@settings(max_examples=100, deadline=None)
@given(responses=st.lists(bola_responses, min_size=1, max_size=60))
def test_bola_summary_matches_independent_classification(responses):
    p = params.BolaParams(mode="noisy", rate=1000.0, start_id=1011, count=len(responses))
    summary = bola.run_bola_enum(_BolaClient(responses), p, USERNAME, "pw", sleep=lambda s: None)

    exp_sent = len(responses)
    exp_cross = sum(1 for s, b in responses
                    if 200 <= s < 300 and b and b.get("tenant_id") not in (None, MY_TENANT))
    exp_fail = sum(1 for s, _ in responses if not 200 <= s < 300)
    assert (summary.requests_sent, summary.cross_tenant_successes, summary.non_success) == (
        exp_sent, exp_cross, exp_fail)

    out = io.StringIO()
    summary.print(out)
    assert out.getvalue().strip() == (
        f"requests_sent={exp_sent} cross_tenant_successes={exp_cross} non_success={exp_fail}")


# ---------------------------------------------------------------- JWT

class _JwtClient:
    """Fails (transport error) according to a per-technique outcome queue."""

    def __init__(self, outcomes):
        self._outcomes = {k: iter(v) for k, v in outcomes.items()}

    def record_token(self, *a, **k):
        pass

    def request(self, method, path, token=None, source_ip=None, technique=None, **k):
        if not next(self._outcomes[technique]):
            raise httpx.ReadTimeout("timeout")
        return _Resp(200)


outcome_lists = st.lists(st.booleans(), min_size=0, max_size=12)


@settings(max_examples=100, deadline=None)
@given(alg=outcome_lists, exp=outcome_lists,
       hij=st.lists(st.booleans(), min_size=0, max_size=12))
def test_jwt_summary_counts_per_technique_and_continues_past_failures(alg, exp, hij):
    outcomes = {"alg_none": alg, "expired": exp, "hijack": hij}
    client = _JwtClient(outcomes)
    report = jwt_sim.JwtAbuseReport()
    noop = lambda: None  # noqa: E731
    jwt_sim.run_alg_none(client, len(alg), report, noop, USER)
    jwt_sim.run_expired_replay(client, len(exp), report, noop, USER)
    jwt_sim.run_hijack(client, len(hij), report, USER, lambda s: None)

    out = io.StringIO()
    report.print_summary(out)
    printed = {m.group(1): (int(m.group(2)), int(m.group(3)))
               for m in re.finditer(r"(\w+): sent=(\d+) failed=(\d+)", out.getvalue())}
    for name, results in outcomes.items():
        assert printed[name] == (len(results), results.count(False))
    assert set(printed) == set(jwt_sim.TECHNIQUES)


def test_jwt_unused_technique_reports_zero():
    report = jwt_sim.JwtAbuseReport()
    out = io.StringIO()
    report.print_summary(out)
    for name in jwt_sim.TECHNIQUES:
        assert f"{name}: sent=0 failed=0" in out.getvalue()


# ---------------------------------------------------------------- SSRF

ssrf_responses = st.one_of(
    st.just(None),  # transport failure
    st.tuples(st.sampled_from(["", "denied", "blocked by policy"]),
              st.sampled_from(["", ssrf.METADATA_CANARY, ssrf.INTERNAL_CANARY]),
              st.sampled_from(["", "tail"]))
    .map(lambda t: "".join(t)),
)


class _SsrfClient:
    def __init__(self, responses):
        self._it = iter(responses)

    def post(self, path, json_body=None, technique=None, **k):
        r = next(self._it)
        if r is None:
            raise httpx.ConnectError("down")
        return _Resp(200, text=r)


@settings(max_examples=100, deadline=None)
@given(responses=st.lists(ssrf_responses, min_size=0, max_size=30))
def test_ssrf_summary_counts_sent_and_canary_responses(responses):
    payloads = [ssrf.Technique("t", f"http://x/{i}") for i in range(len(responses))]
    sent, hits = ssrf.run(_SsrfClient(responses), payloads, 0.0, lambda s: None)
    assert sent == len(responses)
    assert hits == sum(1 for r in responses
                       if r is not None and any(c in r for c in ssrf.CANARIES))
