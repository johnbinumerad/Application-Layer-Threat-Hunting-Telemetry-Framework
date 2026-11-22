import asyncio
import socket

import httpx
import pytest

from app.egress import EgressError, safe_fetch


def _run(url, resolver=None, handler=None, state=None):
    events = []
    st = state if state is not None else {"trace_id": "t1", "source_ip": "1.2.3.4",
                                          "user_id": "u1", "tenant_id": "o1",
                                          "endpoint_template": "/api/v1/webhooks/preview"}
    transport = httpx.MockTransport(handler) if handler else None

    async def go():
        return await safe_fetch(url, st, resolver=resolver, transport=transport,
                                emitter_fn=events.append)
    try:
        res = asyncio.run(go())
        err = None
    except EgressError as e:
        res, err = None, e
    return res, err, events, st


async def _ok(host, port):
    return "169.254.169.254"


def test_success_truncates_and_emits_once():
    seen = {}

    def h(req):
        seen["host"] = req.headers["host"]
        seen["url"] = str(req.url)
        return httpx.Response(200, text="x" * 5000)

    res, err, ev, st = _run("http://meta.lab.internal:8001/p?q=1", _ok, h)
    assert err is None and len(res.body) == 4096
    assert seen["host"] == "meta.lab.internal:8001" and "169.254.169.254" in seen["url"]
    assert len(ev) == 1 and st["egress_count"] == 1
    e = ev[0]
    assert e["event.outcome"] == "success" and e["http.response.status_code"] == 200
    assert e["destination.domain"] == "meta.lab.internal" and e["destination.port"] == 8001
    assert e["destination.ip"] == "169.254.169.254" and e["trace.id"] == "t1"
    assert e["user.id"] == "u1" and e["organization.id"] == "o1"


@pytest.mark.parametrize("url", ["not a url", "http://", "ftp://x", "http://h:99999999/"])
def test_invalid_url(url):
    res, err, ev, _ = _run(url)
    assert err.error_type == "invalid_url" and len(ev) == 1
    assert ev[0]["error.type"] == "invalid_url" and "http.response.status_code" not in ev[0]


@pytest.mark.parametrize("exc,kind", [
    (socket.gaierror("nx"), "dns_failure"),
    (ConnectionRefusedError(), "connection_refused"),
    (httpx.ConnectError("refused"), "connection_refused"),
    (httpx.ConnectTimeout("t"), "timeout"),
    (RuntimeError("boom"), "other"),
])
def test_failures(exc, kind):
    async def r(host, port):
        raise exc
    def h(req):
        raise exc
    res, err, ev, _ = _run("http://127.0.0.1:8001/x", r if isinstance(exc, (socket.gaierror, ConnectionRefusedError)) else _ok, h)
    assert err.error_type == kind and len(ev) == 1
    assert ev[0]["event.outcome"] == "failure" and ev[0]["error.type"] == kind


def test_redirect_not_followed():
    res, err, ev, _ = _run("http://10.0.0.1/", _ok,
                           lambda r: httpx.Response(302, headers={"location": "http://x/"}))
    assert res.status_code == 302 and len(ev) == 1
