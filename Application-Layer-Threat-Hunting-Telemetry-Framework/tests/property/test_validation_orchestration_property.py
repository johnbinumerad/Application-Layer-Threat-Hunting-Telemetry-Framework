"""Property 31: Validation orchestration (fake runners).

**Validates: Requirements 13.1, 13.2**
"""
from hypothesis import given, strategies as st

from labcommon.orchestrator import (
    COMPONENT_ORDER,
    COMPONENT_TIMEOUT_S,
    RunOutcome,
    format_failure,
    run_validation,
)

# Failure modes: non-zero exit (any), timeout, or runner crash.
FAILURES = st.one_of(
    st.one_of(st.integers(-255, -1), st.integers(1, 255)).map(RunOutcome),
    st.just(RunOutcome(None, timed_out=True)),
)


@st.composite
def scenario(draw):
    # fail_at == len(COMPONENT_ORDER) means "no failure"
    fail_at = draw(st.integers(0, len(COMPONENT_ORDER)))
    failure = draw(FAILURES)
    return fail_at, failure


@given(scenario())
def test_orchestration_order_and_stop_on_failure(data):
    fail_at, failure = data
    calls: list[tuple[str, float]] = []
    active = [0]
    overlap = [False]

    def runner(component, timeout_s):
        active[0] += 1
        if active[0] > 1:
            overlap[0] = True
        calls.append((component, timeout_s))
        idx = COMPONENT_ORDER.index(component)
        active[0] -= 1
        return failure if idx == fail_at else RunOutcome(0)

    result = run_validation(runner)

    assert not overlap[0]
    # strict order, each component at most once, with the 30-minute cap
    assert [c for c, _ in calls] == list(COMPONENT_ORDER[: min(fail_at + 1, len(COMPONENT_ORDER))])
    assert all(t == COMPONENT_TIMEOUT_S == 1800 for _, t in calls)
    assert result.telemetry_retained is True

    if fail_at == len(COMPONENT_ORDER):
        assert result.success
        assert result.failed_component is None
        assert result.completed == list(COMPONENT_ORDER)
    else:
        failing = COMPONENT_ORDER[fail_at]
        assert not result.success
        assert result.failed_component == failing
        assert result.completed == list(COMPONENT_ORDER[:fail_at])
        assert [r.component for r in result.results][-1] == failing
        msg = format_failure(result)
        assert failing in msg
        for later in COMPONENT_ORDER[fail_at + 1:]:
            assert later not in [c for c, _ in calls]
        if failure.timed_out:
            assert "timed out" in result.failure_reason
        else:
            assert str(failure.exit_code) in result.failure_reason


@given(st.integers(0, len(COMPONENT_ORDER) - 1))
def test_runner_crash_stops_run(fail_at):
    calls = []

    def runner(component, timeout_s):
        calls.append(component)
        if COMPONENT_ORDER.index(component) == fail_at:
            raise RuntimeError("boom")
        return RunOutcome(0)

    result = run_validation(runner)
    assert result.failed_component == COMPONENT_ORDER[fail_at]
    assert calls == list(COMPONENT_ORDER[: fail_at + 1])
