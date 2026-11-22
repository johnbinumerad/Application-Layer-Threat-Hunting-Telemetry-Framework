"""Property 15: Parameter validation.

**Validates: Requirements 5.4, 5.5, 6.3, 7.1, 7.2, 7.3**
"""
import argparse
import contextlib
import io
import re
from unittest import mock

import httpx
import pytest
from hypothesis import given, strategies as st

from labcommon import params
from simulators import hunt_02_jwt_abuse, traffic_baseline

INT_RE = re.compile(r"^[+-]?[0-9]+$")


def _expected_ok(value, lo, hi):
    """Independent oracle: integer (or integer string) within [lo, hi]."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, int):
        return lo <= value <= hi
    if isinstance(value, str):
        s = value.strip()
        return bool(INT_RE.match(s)) and lo <= int(s) <= hi
    return False


def _inputs(lo, hi):
    around = st.sampled_from([lo - 1, lo, lo + 1, hi - 1, hi, hi + 1, 0, -1])
    return st.one_of(
        st.none(),
        st.integers(-10**7, 10**7),
        around,
        around.map(str),
        st.integers(lo, hi).map(str),
        st.text(max_size=8),
        st.sampled_from(["", "  ", "abc", "1.5", "1e3", "NaN", "inf", "0x10", "٣", "5 5"]),
        st.floats(allow_nan=True, allow_infinity=True),
        st.booleans(),
    )


# (name, validator callable, lo, hi)
CASES = [
    ("duration", params.validate_duration, *params.DURATION_RANGE),
    ("rate", params.validate_rate, *params.RATE_RANGE),
    ("alg_none_count", lambda v: params.validate_jwt_count("alg_none_count", v), 1, 1000),
    ("expired_count", lambda v: params.validate_jwt_count("expired_count", v), 1, 1000),
    ("hijack_count", params.validate_jwt_hijack_count, 2, 1000),
    ("count", lambda v: params.resolve_bola({"count": v}).count, *params.BOLA_COUNT_RANGE),
    ("start_id", lambda v: params.resolve_bola({"start_id": v}).start_id, *params.BOLA_START_ID_RANGE),
]


def test_documented_ranges():
    assert params.DURATION_RANGE == (1, 86_400)
    assert params.RATE_RANGE == (1, 1_000)
    assert params.JWT_COUNT_RANGE == (1, 1_000)
    assert params.JWT_HIJACK_RANGE == (2, 1_000)


@pytest.mark.parametrize("name,fn,lo,hi", CASES)
@given(data=st.data())
def test_accepts_iff_integer_in_range(name, fn, lo, hi, data):
    value = data.draw(_inputs(lo, hi))
    if value is None and name in ("count", "start_id"):
        return  # omitted BOLA count/start-id falls back to the mode preset/default
    if _expected_ok(value, lo, hi):
        result = fn(value)
        assert result == int(value)
    else:
        with pytest.raises(params.ParamError) as ei:
            fn(value)
        assert ei.value.param == name
        assert name.replace("_", "-") in str(ei.value)


@pytest.mark.parametrize("name,fn,lo,hi", CASES)
def test_boundaries(name, fn, lo, hi):
    assert fn(lo) == lo and fn(hi) == hi
    assert fn(str(lo)) == lo and fn(str(hi)) == hi
    for bad in (lo - 1, hi + 1):
        with pytest.raises(params.ParamError):
            fn(bad)


@given(rate=st.one_of(st.none(), st.floats(allow_nan=True, allow_infinity=True),
                      st.text(max_size=6)))
def test_bola_rate(rate):
    ok = False
    if rate is not None:
        try:
            f = float(rate)
            ok = f == f and f not in (float("inf"), float("-inf")) and 1e-6 <= f <= 1000
        except ValueError:
            ok = False
    else:
        ok = True  # preset applies
    if ok:
        params.resolve_bola({"rate": rate})
    else:
        with pytest.raises(params.ParamError) as ei:
            params.resolve_bola({"rate": rate})
        assert ei.value.param == "rate"


@given(duration=_inputs(1, 86_400), rate=_inputs(1, 1_000))
def test_baseline_rejection_names_param_and_sends_nothing(duration, rate):
    ok = _expected_ok(duration, 1, 86_400) and _expected_ok(rate, 1, 1_000)
    if ok:
        return  # acceptance path would start a real run; covered by validator tests
    calls = []

    def handler(request):  # pragma: no cover - must never be called
        calls.append(request)
        return httpx.Response(200)

    args = argparse.Namespace(duration=duration, rate=rate, mode="low-and-slow",
                              target="http://localhost:8080", seed=1)
    buf = io.StringIO()
    with mock.patch.object(traffic_baseline.common, "SimClient") as sim, \
            contextlib.redirect_stderr(buf):
        rc = traffic_baseline.run(args, transport=httpx.MockTransport(handler))
    err = buf.getvalue()
    assert rc == 2
    assert not calls and not sim.called
    bad = "duration" if not _expected_ok(duration, 1, 86_400) else "rate"
    assert f"--{bad}" in err


@given(bad=_inputs(1, 1_000).filter(lambda v: v is not None and not _expected_ok(v, 2, 1000)))
def test_jwt_main_rejects_invalid_hijack_without_sending(bad):
    # argparse type=int would exit on non-int strings; drive main with resolved args instead.
    ns = argparse.Namespace(mode="low-and-slow", alg_none_count=None, expired_count=None,
                            hijack_count=bad, target="http://localhost:8080")
    buf = io.StringIO()
    with mock.patch.object(hunt_02_jwt_abuse, "SimClient") as sim, \
            mock.patch.object(hunt_02_jwt_abuse, "build_parser") as bp:
        bp.return_value.parse_args.return_value = ns
        with contextlib.redirect_stderr(buf):
            rc = hunt_02_jwt_abuse.main([])
    assert rc == 2
    assert not sim.called
    assert "--hijack-count" in buf.getvalue()
