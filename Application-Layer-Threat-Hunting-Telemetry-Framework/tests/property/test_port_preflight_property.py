"""Property 24: Port binding preflight.

**Validates: Requirements 1.6, 9.5, 9.6**
"""
import io

from hypothesis import given, strategies as st

from tools.labctl.up import LOOPBACK, check_ports, run_up

HOST_IPS = st.sampled_from([LOOPBACK, "0.0.0.0", "", "192.168.1.5", "::", "10.0.0.1"])


@st.composite
def compose_and_busy(draw):
    n = draw(st.integers(0, 8))
    ports = draw(st.lists(st.integers(1024, 65000), min_size=n, max_size=n, unique=True))
    services = {}
    for i, port in enumerate(ports):
        services.setdefault(f"svc{i % 3}", {"ports": []})["ports"].append(
            {"host_ip": draw(HOST_IPS), "published": str(port), "target": 80, "protocol": "tcp"}
        )
    busy = set(draw(st.lists(st.sampled_from(ports), unique=True))) if ports else set()
    return {"services": services}, busy


@given(compose_and_busy())
def test_preflight_accepts_iff_loopback_and_free(data):
    config, busy = data
    errors = check_ports(config, lambda p: p not in busy)
    entries = [(s, p) for s, v in config["services"].items() for p in v["ports"]]
    expected_ok = all(p["host_ip"] == LOOPBACK for _, p in entries) and not any(
        int(p["published"]) in busy for _, p in entries
    )
    assert (errors == []) == expected_ok
    text = "\n".join(errors)
    for _, p in entries:
        if p["host_ip"] != LOOPBACK or int(p["published"]) in busy:
            assert p["published"] in text

    calls = []
    err = io.StringIO()
    code = run_up(lambda: config, lambda argv: calls.append(argv) or 0, lambda p: p not in busy, err)
    if expected_ok:
        assert code == 0 and calls == [["docker", "compose", "up", "-d"]]
    else:
        assert code != 0 and calls == [["docker", "compose", "down"]]
        assert err.getvalue().strip()
