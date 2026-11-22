"""Property 22: Target safety validation.

**Validates: Requirements 9.1, 9.2, 9.3**
"""
import io
import time

import pytest
from hypothesis import given, strategies as st

from labcommon import safety
from labcommon.safety import GatewayConfig, validate_target

GW = GatewayConfig(bind_host="127.0.0.1", port=8080, scheme="http")


class FakeHttpClient:
    def __init__(self):
        self.calls = 0

    def get(self, *a, **k):
        self.calls += 1


def run_simulator(url, resolver, client, timeout=safety.RESOLVE_TIMEOUT_S):
    """Mimic a simulator entry: validate first, then send requests."""
    err = io.StringIO()
    try:
        validate_target(url, GW, resolver, timeout, stderr=err)
    except SystemExit as e:
        return e.code, err.getvalue()
    client.get(url)
    return 0, err.getvalue()


_hosts = st.sampled_from(
    ["127.0.0.1", "localhost", "[::1]", "10.0.0.5", "169.254.169.254", "evil.example", "target-api", "0x7f.0.0.1"]
)
_schemes = st.sampled_from(["http", "https", "ftp", "gopher"])
_ports = st.sampled_from([None, 80, 443, 8080, 8081, 8001, 65535])
_addr = st.sampled_from(["127.0.0.1", "127.0.0.2", "::1", "10.0.0.5", "169.254.169.254", "192.0.2.1"])
_results = st.one_of(
    st.lists(_addr, min_size=0, max_size=4),
    st.sampled_from([OSError("nxdomain"), RuntimeError("boom")]),
)


def _make_resolver(result):
    def resolver(host, port):
        if isinstance(result, Exception):
            raise result
        return list(result)

    return resolver


def _expected_accept(scheme, port, result):
    return (
        scheme == "http"
        and port == 8080
        and not isinstance(result, Exception)
        and len(result) > 0
        and all(a == "127.0.0.1" for a in result)
    )


@given(scheme=_schemes, host=_hosts, port=_ports, result=_results)
def test_accepts_iff_equals_gateway(scheme, host, port, result):
    url = f"{scheme}://{host}" + (f":{port}" if port is not None else "") + "/api/v1/lab/status"
    client = FakeHttpClient()
    start = time.monotonic()
    code, err = run_simulator(url, _make_resolver(result), client)
    assert time.monotonic() - start < 5
    if _expected_accept(scheme, port, result):
        assert code == 0
        assert client.calls == 1
    else:
        assert code == 2
        assert "outside the Lab" in err
        assert client.calls == 0


@given(url=st.sampled_from(["", "http://", "http://:8080/", "http://127.0.0.1:notaport/", "http://[::1/", "not a url"]))
def test_malformed_urls_rejected(url):
    client = FakeHttpClient()
    code, err = run_simulator(url, _make_resolver(["127.0.0.1"]), client)
    assert code == 2 and "outside the Lab" in err and client.calls == 0


def test_hanging_resolver_rejected_within_5_seconds():
    def slow(host, port):
        time.sleep(4)
        return ["127.0.0.1"]

    client = FakeHttpClient()
    start = time.monotonic()
    code, err = run_simulator("http://localhost:8080/", slow, client)
    assert time.monotonic() - start < 5
    assert code == 2 and "outside the Lab" in err and client.calls == 0


def test_gateway_target_accepted():
    client = FakeHttpClient()
    code, _ = run_simulator("http://127.0.0.1:8080/", _make_resolver(["127.0.0.1"]), client)
    assert code == 0 and client.calls == 1
