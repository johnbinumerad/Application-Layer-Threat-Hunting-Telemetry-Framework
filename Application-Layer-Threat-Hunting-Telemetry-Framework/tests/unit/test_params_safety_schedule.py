import io

import pytest

from labcommon import params, safety, schedule

GW = safety.GatewayConfig("127.0.0.1", 8080, "http")


def test_int_validation_boundaries():
    assert params.validate_duration("1") == 1 and params.validate_duration(86400) == 86400
    for bad in (0, 86401, "abc", "1.5", None, "", True):
        with pytest.raises(params.ParamError) as e:
            params.validate_duration(bad)
        assert e.value.param == "duration"
    with pytest.raises(params.ParamError):
        params.validate_jwt_hijack_count(1)


def test_mode_override():
    assert params.resolve_bola({"mode": "noisy"}).rate == 50
    assert params.resolve_bola({"mode": "noisy", "rate": "2"}).rate == 2
    assert params.resolve_bola({}).rate == 0.5
    with pytest.raises(params.ParamError) as e:
        params.resolve_bola({"rate": 5000})
    assert e.value.param == "rate"


def test_schedule_rolling_window():
    for rate in (0.5, 1, 3.7):
        offs = schedule.request_offsets(500, rate)
        assert schedule.max_in_window(offs) <= max(1, int(rate * 60))


def test_safety():
    ok = lambda h, p: ["127.0.0.1"]
    safety.validate_target("http://localhost:8080/x", GW, ok)
    for url, res in [("https://localhost:8080", ok), ("http://localhost:9", ok),
                     ("http://x:8080", lambda h, p: ["127.0.0.1", "8.8.8.8"]),
                     ("http://x:8080", lambda h, p: [])]:
        err = io.StringIO()
        with pytest.raises(SystemExit) as e:
            safety.validate_target(url, GW, res, stderr=err)
        assert e.value.code == 2 and "outside the Lab" in err.getvalue()
