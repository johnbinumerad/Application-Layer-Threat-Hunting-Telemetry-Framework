"""Property 10: Egress event per outbound request.

**Validates: Requirements 3.6, 3.7, 8.3, 8.7, 2.11**
"""
import asyncio
import socket

import httpx
from hypothesis import given, strategies as st

from app.egress import EgressError, safe_fetch

_LABEL = st.from_regex(r"[a-z][a-z0-9-]{0,10}", fullmatch=True)
_HOSTNAMES = st.builds(lambda a, b: f"{a}.{b}.example", _LABEL, _LABEL) | st.sampled_from(
    ["localhost", "metadata.internal", "internal-svc"])
_IP_FORMS = st.sampled_from([
    "127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.9",
    "2130706433", "0177.0.0.1", "0x7f.0.0.1", "0x7f000001", "[::1]",
    "[::ffff:127.0.0.1]", "[::ffff:a9fe:a9fe]", "[fd00::1]",
])
_MALFORMED = st.sampled_from([
    "", "not a url", "ftp://example.com/x", "http://", "file:///etc/passwd",
    "http://host:99999/", "http://host:abc/", "http://[::1/", "//nohost/path",
])
_PORT = st.one_of(st.none(), st.integers(1, 65535))


@st.composite
def valid_urls(draw):
    host = draw(_HOSTNAMES | _IP_FORMS)
    scheme = draw(st.sampled_from(["http", "https"]))
    port = draw(_PORT)
    path = draw(st.sampled_from(["", "/", "/latest/meta-data/", "/a/b?x=1"]))
    return f"{scheme}://{host}" + (f":{port}" if port else "") + path


_OUTCOMES = st.one_of(
    st.tuples(st.just("success"), st.integers(100, 599)),
    st.tuples(st.sampled_from(["dns_failure", "connection_refused", "timeout"]), st.none()),
)


def _run(url, outcome):
    kind, status = outcome
    events, resolved, requests = [], [], []

    async def resolver(host, port):
        resolved.append((host, port))
        if kind == "dns_failure":
            raise socket.gaierror("nope")
        return "10.9.8.7"

    def handler(request):
        requests.append(request)
        if kind == "connection_refused":
            raise httpx.ConnectError("refused")
        if kind == "timeout":
            raise httpx.ReadTimeout("slow")
        return httpx.Response(status, text="body")

    state = {"trace_id": "t" * 32, "source_ip": "198.51.100.7"}
    err = None
    try:
        asyncio.run(safe_fetch(url, state, resolver=resolver,
                               transport=httpx.MockTransport(handler),
                               emitter_fn=events.append))
    except EgressError as exc:
        err = exc
    return events, resolved, requests, err, state


@given(valid_urls(), _OUTCOMES)
def test_exactly_one_egress_event_for_any_destination_and_outcome(url, outcome):
    kind, status = outcome
    events, resolved, requests, err, state = _run(url, outcome)

    assert len(events) == 1
    assert state["egress_count"] == 1
    ev = events[0]
    assert ev["event.dataset"] == "appsec.egress"
    assert ev["trace.id"] == "t" * 32
    assert ev["url.full"] == url
    assert resolved, "resolver must be consulted (no destination filtering)"
    host, port = resolved[0]
    assert ev["destination.port"] == port
    assert ev["destination.address"] == host
    if kind == "dns_failure":
        assert "destination.ip" not in ev
    else:
        assert ev["destination.ip"] == "10.9.8.7"

    if kind == "success":
        assert err is None
        assert requests, "internal destinations are fetched, not filtered"
        assert ev["event.outcome"] == "success"
        assert ev["http.response.status_code"] == status
        assert "error.type" not in ev
    else:
        assert err is not None and err.error_type == kind
        assert ev["event.outcome"] == "failure"
        assert "http.response.status_code" not in ev
        assert ev["error.type"] == kind


@given(_MALFORMED)
def test_malformed_url_emits_single_failure_event(url):
    events, resolved, requests, err, state = _run(url, ("success", 200))
    assert len(events) == 1
    assert state["egress_count"] == 1
    assert err is not None and err.error_type == "invalid_url"
    ev = events[0]
    assert ev["event.outcome"] == "failure"
    assert ev["error.type"] == "invalid_url"
    assert "http.response.status_code" not in ev
    assert ev["trace.id"] == "t" * 32
    assert not resolved and not requests
