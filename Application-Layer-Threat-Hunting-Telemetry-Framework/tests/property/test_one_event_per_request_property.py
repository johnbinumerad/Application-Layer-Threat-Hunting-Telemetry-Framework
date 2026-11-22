"""Property 6: Exactly one telemetry event per request.

**Validates: Requirements 3.1**
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, strategies as st

from app import main as app_main
from app.db import Database
from app.main import create_app
from app.seed import seed_users_spec


class ListEmitter:
    def __init__(self):
        self.events = []

    def emit(self, attrs):
        self.events.append(dict(attrs))


class _Fetched:
    status_code = 200
    body = "ok"


async def _fake_fetch(url, state, ground_truth=None):
    return _Fetched()


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def env():
    mp = pytest.MonkeyPatch()
    mp.setattr(app_main, "safe_fetch", _fake_fetch)  # no real network egress
    em = ListEmitter()
    api = create_app(Database(":memory:"), em, metadata_probe=lambda: True)

    @api.get("/boom")
    async def boom():
        raise RuntimeError("handler exception")

    client = TestClient(api, raise_server_exceptions=False)
    user = seed_users_spec()[0]
    login = client.post("/api/v1/auth/login",
                        json={"username": user["username"], "password": user["password"]})
    assert login.status_code == 200
    token = login.json()["access_token"]
    em.events.clear()
    yield client, em, token
    mp.undo()


KNOWN_PATHS = ["/api/v1/auth/login", "/api/v1/invoices/1001", "/api/v1/invoices/1011",
               "/api/v1/invoices/abc", "/api/v1/invoices/9999", "/api/v1/webhooks/preview",
               "/api/v1/admin/audit", "/api/v1/lab/status", "/boom", "/", "/nope"]
paths = st.one_of(
    st.sampled_from(KNOWN_PATHS),
    st.text(alphabet="abcxyz019/-_.%", min_size=0, max_size=20).map(lambda s: "/" + s.lstrip("/")),
)
methods = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
token_kinds = st.sampled_from(["none", "valid", "garbage", "alg_none", "empty_bearer", "tampered"])
bodies = st.one_of(
    st.none(),
    st.binary(max_size=40),
    st.just(b"{}"),
    st.just(b'{"username": "x", "password": "y"}'),
    st.just(b'{"url": "http://example.com/"}'),
    st.just(b'{"url": 5}'),
    st.just(b"{not json"),
)


@given(method=methods, path=paths, kind=token_kinds, body=bodies)
def test_exactly_one_api_event_per_request(env, method, path, kind, body):
    client, em, token = env
    headers = {}
    if kind == "valid":
        headers["Authorization"] = f"Bearer {token}"
    elif kind == "garbage":
        headers["Authorization"] = "Bearer not.a.jwt"
    elif kind == "alg_none":
        headers["Authorization"] = "Bearer " + _b64({"alg": "none", "typ": "JWT"}) + "." + \
            _b64({"sub": "u", "role": "admin", "tenant_id": "t"}) + "."
    elif kind == "empty_bearer":
        headers["Authorization"] = "Bearer "
    elif kind == "tampered":
        headers["Authorization"] = f"Bearer {token}x"
    if body is not None:
        headers["Content-Type"] = "application/json"

    em.events.clear()
    resp = client.request(method, path, headers=headers, content=body)

    api_events = [e for e in em.events if e.get("event.dataset") == "appsec.api"]
    assert len(api_events) == 1, (method, path, kind, em.events)
    assert api_events[0]["http.response.status_code"] == resp.status_code
