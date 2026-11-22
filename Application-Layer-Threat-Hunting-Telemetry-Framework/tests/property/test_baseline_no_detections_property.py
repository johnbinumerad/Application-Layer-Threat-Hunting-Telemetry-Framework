"""Property 27: Baseline raises no detections.

**Validates: Requirements 11.5**

For any seed and valid baseline parameters, the events produced by the baseline plan
(modelled with the app's response model: own-tenant invoice GETs return 200 with
``cross_tenant=False``; requests before a user's login are unauthenticated 401s) are
flagged by none of the BOLA, JWT or SSRF detections.
"""
import uuid
from datetime import datetime, timedelta, timezone

from hypothesis import given, settings, strategies as st

from labcommon import evaluator
from labcommon.schema import DetectionConfig, GroundTruth, TelemetryEvent
from simulators import traffic_baseline as tb

USERS = tb.build_users()
CFG = DetectionConfig.load()
USER_AGENT = "lab-sim/1.0"
INVOICE_TEMPLATE = "/api/v1/invoices/{invoice_id}"
GT = GroundTruth(label="baseline", scenario="baseline", technique="normal_use")


def baseline_events(duration, rate, seed, start):
    """Flat ECS attribute dicts for the baseline plan, as the app would emit them."""
    jtis: dict[int, str] = {}
    out = []
    for pr in tb.plan_requests(USERS, duration, rate, seed):
        u = USERS[pr.user_index]
        ts = start + timedelta(seconds=pr.offset)
        common = dict(
            trace_id=pr.request_id, source_ip=u.source_ip, start=ts, duration_ns=5_000_000,
            user_agent=USER_AGENT, ground_truth=GT,
        )
        if pr.kind == "login":
            jtis[pr.user_index] = str(uuid.UUID(int=(seed << 8) + pr.user_index))
            ev = TelemetryEvent(
                action="auth_login", outcome="success", method="POST", status_code=200,
                path=pr.path, endpoint_template=pr.path, user_id=u.username,
                tenant_id=u.tenant_id, user_roles=["user"], **common)
        elif pr.user_index in jtis:
            ev = TelemetryEvent(
                action="api_request", outcome="success", method="GET", status_code=200,
                path=pr.path, endpoint_template=INVOICE_TEMPLATE, user_id=u.username,
                tenant_id=u.tenant_id, user_roles=["user"],
                resource_id=pr.path.rsplit("/", 1)[1], resource_tenant_id=u.tenant_id,
                cross_tenant=False, jwt_jti=jtis[pr.user_index], jwt_alg="HS256",
                jwt_expired=False, jwt_verified=True, **common)
        else:  # no token yet: unauthenticated request rejected with 401
            ev = TelemetryEvent(
                action="api_request", outcome="failure", method="GET", status_code=401,
                path=pr.path, endpoint_template=INVOICE_TEMPLATE, **common)
        attrs = ev.to_attributes()
        # derived by the collector's transform/enrich stage
        attrs["appsec.client_pair"] = f"{attrs['source.ip']}|{attrs['user_agent.original']}"
        out.append(attrs)
    return out


@settings(max_examples=40, deadline=None)
@given(
    duration=st.integers(1, 600),
    rate=st.integers(1, 10),
    seed=st.integers(0, 2**32 - 1),
    start=st.datetimes(min_value=datetime(2024, 1, 1), max_value=datetime(2030, 1, 1)),
    anchor=st.integers(0, 599),
)
def test_baseline_raises_no_detections(duration, rate, seed, start, anchor):
    events = baseline_events(duration, rate, seed, start.replace(tzinfo=timezone.utc))
    assert events
    assert evaluator.evaluate(events, CFG, anchor_offset_seconds=anchor) == []
