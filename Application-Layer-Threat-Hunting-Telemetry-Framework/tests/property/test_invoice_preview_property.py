"""Property tests for invoice access (Property 4) and preview behavior (Property 5)."""
import socket

import httpx
from fastapi.testclient import TestClient
from hypothesis import given, strategies as st

import app.main as main_mod
from app import auth, egress
from app.db import Database
from app.main import create_app
from app.seed import seed_users_spec

USERS = seed_users_spec()
DB = Database(":memory:")


class _NullEmitter:
    def emit(self, attrs):
        pass


_CLIENT = TestClient(create_app(DB, _NullEmitter(), metadata_probe=lambda: True),
                     raise_server_exceptions=False)
STORED = {i["id"]: i for i in DB.list_invoices()}
INVOICE_IDS = sorted(STORED)

_SQLITE_MAX = 2**63 - 1


def _headers(user: dict) -> dict:
    return {"Authorization": f"Bearer {auth.issue_token(user)}"}


async def _resolver(host: str, port: int) -> str:
    return "93.184.216.34"


class _Hooks:
    """Route app.main.safe_fetch through injected transport/resolver (no real network)."""

    def __init__(self):
        self.transport = None
        self.resolver = _resolver
        self._orig = main_mod.safe_fetch

    def __enter__(self):
        orig = self._orig
        hooks = self

        async def patched(url, state=None, **kw):
            return await orig(url, state, resolver=hooks.resolver, transport=hooks.transport,
                              emitter_fn=lambda a: None, **kw)

        main_mod.safe_fetch = patched
        return self

    def __exit__(self, *exc):
        main_mod.safe_fetch = self._orig


def _preview(body_text=None, *, transport=None, resolver=None, url="http://example.test/p"):
    with _Hooks() as h:
        if body_text is not None:
            h.transport = httpx.MockTransport(
                lambda req: httpx.Response(200, content=body_text.encode("utf-8")))
        if transport is not None:
            h.transport = transport
        if resolver is not None:
            h.resolver = resolver
        return _CLIENT.post("/api/v1/webhooks/preview", json={"url": url},
                            headers=_headers(USERS[0]))


# Feature: application-layer-threat-hunting-framework, Property 4: Invoice access without tenant check
# **Validates: Requirements 2.4, 2.9**
@given(st.sampled_from(USERS), st.sampled_from(INVOICE_IDS))
def test_property_4_existing_invoice_returned_across_tenants(user, invoice_id):
    r = _CLIENT.get(f"/api/v1/invoices/{invoice_id}", headers=_headers(user))
    assert r.status_code == 200
    assert r.json() == STORED[invoice_id]


@given(st.sampled_from(USERS),
       st.integers(min_value=-_SQLITE_MAX, max_value=_SQLITE_MAX).filter(lambda i: i not in STORED))
def test_property_4_missing_invoice_is_404(user, invoice_id):
    r = _CLIENT.get(f"/api/v1/invoices/{invoice_id}", headers=_headers(user))
    assert r.status_code == 404
    assert "customer" not in r.text and "amount_cents" not in r.text


def test_property_4_cross_tenant_example():
    user = next(u for u in USERS if u["tenant_id"] == "tnt_001")
    other = next(i for i in INVOICE_IDS if STORED[i]["tenant_id"] != user["tenant_id"])
    r = _CLIENT.get(f"/api/v1/invoices/{other}", headers=_headers(user))
    assert r.status_code == 200 and r.json() == STORED[other]


# Feature: application-layer-threat-hunting-framework, Property 5: Preview truncation and failure handling
# **Validates: Requirements 2.6, 2.7, 2.8**
@given(st.text(max_size=6000))
def test_property_5_preview_is_first_4096_chars(body):
    r = _preview(body)
    assert r.status_code == 200
    assert r.json()["body"] == body[:4096]


@given(st.text().filter(lambda s: ":" not in s))
def test_property_5_malformed_url_is_error_without_preview(url):
    r = _preview("SECRET-PREVIEW-CONTENT", url=url)
    assert r.status_code == 400
    assert r.json().get("reason") == "invalid_url"
    assert "SECRET-PREVIEW-CONTENT" not in r.text and "body" not in r.json()


@given(st.sampled_from(["dns_failure", "connection_refused", "timeout"]),
       st.text(min_size=1, max_size=50))
def test_property_5_injected_failures_name_reason_and_no_content(kind, marker):
    def handler(req):
        if kind == "connection_refused":
            raise httpx.ConnectError(marker)
        if kind == "timeout":
            raise httpx.ReadTimeout(marker)
        return httpx.Response(200, content=b"SECRET-PREVIEW-CONTENT")

    async def resolver(host, port):
        if kind == "dns_failure":
            raise socket.gaierror(marker)
        return "93.184.216.34"

    r = _preview(transport=httpx.MockTransport(handler), resolver=resolver)
    assert r.status_code == 502
    j = r.json()
    assert j["reason"] == kind
    assert "body" not in j and "SECRET-PREVIEW-CONTENT" not in r.text


def test_property_5_constants():
    assert egress.PREVIEW_CHARS == 4096
