"""Property 30: Validation determinism.

**Validates: Requirements 13.5**

For any labelled event set, configuration, and anchor, computing alerts and
metrics twice yields identical TP/FP/FN counts per detection, independent of
event arrival order.
"""
from hypothesis import given, settings, strategies as st

from labcommon.evaluator import evaluate
from labcommon.metrics import compute_metrics
from labcommon.schema import DetectionConfig

CFG = DetectionConfig.load()
BASE = 1_700_000_000 - (1_700_000_000 % 600)


@st.composite
def labelled_event(draw, idx):
    ev = {
        "event.id": f"e{idx}",
        "event_id": f"e{idx}",
        "event.dataset": draw(st.sampled_from(["appsec.api", "appsec.egress"])),
        "@timestamp": BASE + draw(st.integers(0, 1800)),
        "user.id": draw(st.sampled_from(["u1", "u2"])),
        "user.roles": [draw(st.sampled_from(["user", "admin", "batch_worker"]))],
        "appsec.endpoint_template": draw(st.sampled_from(["/api/invoices/{id}", "/api/x"])),
        "appsec.resource_id": f"r{draw(st.integers(0, 40))}",
        "http.response.status_code": draw(st.sampled_from([200, 403, 404])),
        "appsec.jwt.jti": draw(st.sampled_from(["jA", "jB"])),
        "appsec.client_pair": draw(st.sampled_from(["p1", "p2"])),
        "label": draw(st.sampled_from(["attack", "baseline"])),
    }
    if draw(st.booleans()):
        ev["appsec.jwt.alg"] = draw(st.sampled_from(["none", "HS256"]))
    if draw(st.booleans()):
        ev["destination.ip"] = draw(st.sampled_from(
            ["10.0.0.1", "169.254.169.254", "127.0.0.1", "8.8.8.8"]))
    if draw(st.booleans()):
        ev["role"] = "setup"
    return ev


@st.composite
def event_sets(draw):
    n = draw(st.integers(0, 60))
    return [draw(labelled_event(i)) for i in range(n)]


def _per_detection_counts(events, anchor):
    dets = evaluate(events, CFG, anchor_offset_seconds=anchor)
    groups = {}
    for d in dets:
        groups.setdefault((d.scenario, d.rule), set()).update(d.event_ids)
    return {k: compute_metrics(events, ids).as_dict() for k, ids in groups.items()}, \
        compute_metrics(events, {i for ids in groups.values() for i in ids}).as_dict()


@settings(max_examples=150, deadline=None)
@given(events=event_sets(), anchor=st.sampled_from([0, 1, 59, 300, 599]), data=st.data())
def test_validation_is_deterministic_and_order_independent(events, anchor, data):
    first = _per_detection_counts(events, anchor)
    second = _per_detection_counts(events, anchor)
    assert first == second
    shuffled = data.draw(st.permutations(events))
    assert _per_detection_counts(shuffled, anchor) == first
