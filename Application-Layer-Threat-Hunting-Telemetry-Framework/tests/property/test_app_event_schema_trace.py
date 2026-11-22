"""Properties 7 and 8 against events captured from the running ASGI app.

Feature: application-layer-threat-hunting-framework, Property 7: Event schema and field mapping
Feature: application-layer-threat-hunting-framework, Property 8: Trace_ID propagation

**Validates: Requirements 3.2, 3.3, 3.4, 3.5, 3.10, 3.6, 8.3**
"""
import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import given, strategies as st

from app import egress, main as app_main, telemetry
from app.db import Database
from app.main import create_app
from app.seed import seed_users_spec
from labcommon.schema import load_field_mapping

_MAPPING = load_field_mapping()
# App sends two Sensitive_Fields to the Collector, which removes them before indexing.
MAPPING_KEYS = set(_MAPPING["fields"].keys()) | set(_MAPPING["removed_before_indexing"])
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
TEMPLATE = "/api/v1/invoices/{invoice_id}"


class ListEmitter:
    def __init__(self):
        self.events = []

    def emit(self, attrs):
        self.events.append(dict(attrs))


@pytest.fixture(scope="module")
def env():
    em = ListEmitter()
    telemetry.set_emitter(em)  # egress events go through the global emitter
    real_fetch = egress.safe_fetch

    async def resolver(host, port):
        return "192.0.2.10"

    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))

    async def fetch(url, state, ground_truth=None):
        return await real_fetch(url, state, ground_truth=ground_truth,
                                resolver=resolver, transport=transport)

    mp = pytest.MonkeyPatch()
    mp.setattr(app_main, "safe_fetch", fetch)
    db = Database(":memory:")
    client = TestClient(create_app(db, em, metadata_probe=lambda: True),
                        raise_server_exceptions=False)
    u = seed_users_spec()[0]
    token = client.post("/api/v1/auth/login",
                        json={"username": u["username"], "password": u["password"]}
                        ).json()["access_token"]
    em.events.clear()
    yield client, em, token
    mp.undo()
    telemetry.set_emitter(None)


ascii_ua = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126),
                   min_size=0, max_size=700)
trace_ids = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_", min_size=1, max_size=64)
invoice_ids = st.one_of(st.integers(0, 10**6).map(str),
                        st.text(alphabet="abcxyz0123456789", min_size=1, max_size=10))
token_mode = st.sampled_from(["none", "valid", "garbage"])


def _headers(token, mode, extra=None):
    h = dict(extra or {})
    if mode == "valid":
        h["Authorization"] = f"Bearer {token}"
    elif mode == "garbage":
        h["Authorization"] = "Bearer not.a.jwt"
    return h


def _check_event(attrs):
    decoded = json.loads(json.dumps(attrs))
    assert isinstance(decoded, dict)
    assert TS_RE.match(attrs["@timestamp"])
    lat = attrs["appsec.latency_ms"]
    assert isinstance(lat, int) and not isinstance(lat, bool) and lat >= 0
    assert set(attrs) <= MAPPING_KEYS, set(attrs) - MAPPING_KEYS
    for key, value in attrs.items():
        assert value is not None and value != "" and value != [], key
    if "user_agent.original" in attrs:
        assert len(attrs["user_agent.original"]) <= 512


# Feature: application-layer-threat-hunting-framework, Property 7: Event schema and field mapping
@given(invoice_id=invoice_ids, mode=token_mode, ua=ascii_ua,
       method=st.sampled_from(["GET", "PUT", "DELETE"]))
def test_app_invoice_event_schema(env, invoice_id, mode, ua, method):
    client, em, token = env
    em.events.clear()
    headers = _headers(token, mode, {"User-Agent": ua} if ua else {})
    resp = client.request(method, f"/api/v1/invoices/{invoice_id}", headers=headers)
    assert len(em.events) == 1
    attrs = em.events[0]
    _check_event(attrs)
    assert attrs["http.response.status_code"] == resp.status_code
    assert attrs["appsec.endpoint_template"] == TEMPLATE
    assert attrs["appsec.resource_id"] == invoice_id
    if ua:
        assert attrs["user_agent.original"] == ua[:512]
    if mode == "none":
        for key in ("user.id", "organization.id", "appsec.jwt.jti"):
            assert key not in attrs


# Feature: application-layer-threat-hunting-framework, Property 7: Event schema and field mapping
@given(path=st.text(alphabet="abcdefg/-_.0123456789", min_size=1, max_size=30).map(lambda s: "/zz" + s),
       mode=token_mode)
def test_app_unmatched_event_schema(env, path, mode):
    client, em, token = env
    em.events.clear()
    resp = client.get(path, headers=_headers(token, mode))
    assert len(em.events) == 1
    attrs = em.events[0]
    _check_event(attrs)
    assert attrs["appsec.endpoint_template"] == "unmatched"
    assert "appsec.resource_id" not in attrs
    assert attrs["http.response.status_code"] == resp.status_code


# Feature: application-layer-threat-hunting-framework, Property 8: Trace_ID propagation
@given(tid=trace_ids, mode=token_mode, invoice_id=st.integers(0, 10**5))
def test_trace_id_equals_request_id_header(env, tid, mode, invoice_id):
    client, em, token = env
    em.events.clear()
    client.get(f"/api/v1/invoices/{invoice_id}", headers=_headers(token, mode, {"x-request-id": tid}))
    assert len(em.events) == 1
    assert em.events[0]["trace.id"] == tid


# Feature: application-layer-threat-hunting-framework, Property 8: Trace_ID propagation
@given(n=st.integers(2, 25), mode=token_mode)
def test_generated_trace_ids_pairwise_unique(env, n, mode):
    client, em, token = env
    em.events.clear()
    for i in range(n):
        client.get(f"/api/v1/invoices/{i}", headers=_headers(token, mode))
    ids = [e["trace.id"] for e in em.events]
    assert len(ids) == n
    assert all(ids) and len(set(ids)) == n


# Feature: application-layer-threat-hunting-framework, Property 8: Trace_ID propagation
@given(tid=st.one_of(st.none(), trace_ids),
       urls=st.lists(st.sampled_from(["http://example.test/a", "http://10.0.0.5:8080/x",
                                      "https://svc.internal/p?q=1"]), min_size=1, max_size=1))
def test_egress_events_carry_request_trace_id(env, tid, urls):
    client, em, token = env
    em.events.clear()
    headers = _headers(token, "valid", {"x-request-id": tid} if tid else {})
    resp = client.post("/api/v1/webhooks/preview", json={"url": urls[0]}, headers=headers)
    assert resp.status_code == 200
    api = [e for e in em.events if e["event.dataset"] == "appsec.api"]
    eg = [e for e in em.events if e["event.dataset"] == "appsec.egress"]
    assert len(api) == 1 and len(eg) == 1
    _check_event(eg[0])
    assert eg[0]["trace.id"] == api[0]["trace.id"]
    if tid:
        assert eg[0]["trace.id"] == tid
