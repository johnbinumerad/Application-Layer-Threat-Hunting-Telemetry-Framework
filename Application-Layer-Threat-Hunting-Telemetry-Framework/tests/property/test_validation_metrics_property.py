"""Property 29: Validation metrics.

**Validates: Requirements 13.3, 13.4**
"""

from __future__ import annotations

from fractions import Fraction

from hypothesis import given, strategies as st

from labcommon.metrics import NOT_APPLICABLE, compute_metrics, precision_percent


@st.composite
def scenario(draw):
    n = draw(st.integers(0, 40))
    events = []
    for i in range(n):
        events.append(
            {
                "event_id": f"ev-{i}",
                "label": draw(st.sampled_from(["attack", "baseline"])),
                "role": draw(st.sampled_from(["attack", "setup", "victim", None])),
            }
        )
    ids = [e["event_id"] for e in events]
    alerted = set(draw(st.sets(st.sampled_from(ids)))) if ids else set()
    # Alerted ids unknown to the event set must be ignored.
    extra = draw(st.sets(st.sampled_from(["x-1", "x-2", "x-3"])))
    return events, alerted, extra


def _round_half_up_1dp(num: int, den: int) -> float:
    scaled = Fraction(num * 10, den)  # percent * 10
    return (int((scaled + Fraction(1, 2)) // 1)) / 10


@given(scenario())
def test_metrics_match_definition(s):
    events, alerted, extra = s
    m = compute_metrics(events, alerted | extra)

    tp = sum(1 for e in events if e["label"] == "attack" and e["event_id"] in alerted)
    fp = sum(1 for e in events if e["label"] == "baseline" and e["event_id"] in alerted)
    fn = sum(
        1
        for e in events
        if e["label"] == "attack"
        and e["event_id"] not in alerted
        and e["role"] != "setup"
    )
    assert (m.tp, m.fp, m.fn) == (tp, fp, fn)

    if tp + fp == 0:
        assert m.precision == NOT_APPLICABLE
    else:
        assert m.precision == _round_half_up_1dp(tp * 100, tp + fp)
        assert 0.0 <= m.precision <= 100.0


@given(scenario())
def test_setup_events_never_false_negatives(s):
    events, _, _ = s
    setup_only = [dict(e, role="setup") for e in events]
    assert compute_metrics(setup_only, set()).fn == 0


@given(st.integers(0, 500), st.integers(0, 500))
def test_precision_percent_direct(tp, fp):
    p = precision_percent(tp, fp)
    if tp + fp == 0:
        assert p == NOT_APPLICABLE
    else:
        assert p == _round_half_up_1dp(tp * 100, tp + fp)


def test_precision_examples():
    assert precision_percent(0, 0) == NOT_APPLICABLE
    assert precision_percent(1, 2) == 33.3
    assert precision_percent(2, 1) == 66.7
    assert precision_percent(0, 5) == 0.0
    assert precision_percent(5, 0) == 100.0
