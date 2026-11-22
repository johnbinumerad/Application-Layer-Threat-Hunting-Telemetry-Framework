"""Smoke tests for app.main routes and the management app."""
import httpx
import pytest
from fastapi.testclient import TestClient

from app import egress
from app.db import Database
from app.main import create_app, create_management_app
from app.seed import lab_password, seed_users_spec


class ListEmitter:
    def __init__(self):
        self.events = []

    def emit(self, attrs):
        self.events.append(dict(attrs))


@pytest.fixture()
def env():
    db = Database(":memory:")
    em = ListEmitter()
    app = create_app(db, em, metadata_probe=lambda: True)
    return TestClient(app, raise_server_exceptions=False), em, db


def _login(client, n=1):
    u = seed_users_spec()[n - 1]
    r = client.post("/api/v1/auth/login", json={"username": u["username"], "password": u["password"]})
    return r


def test_login_and_bola(env):
    client, em, _ = env
    r = _login(client)
    assert r.status_code == 200
    h = {"Authorization": "Bearer " + r.json()["access_token"]}
    own = client.get("/api/v1/invoices/1001", headers=h)
    other = client.get("/api/v1/invoices/1011", headers=h)
    assert own.status_code == 200 and other.status_code == 200
    assert client.get("/api/v1/invoices/9999", headers=h).status_code == 404
    assert client.get("/api/v1/invoices/1001").status_code == 401
    ev = [e for e in em.events if e.get("appsec.resource_id") == "1011"][0]
    assert ev["appsec.endpoint_template"] == "/api/v1/invoices/{invoice_id}"
    assert ev["appsec.authz.cross_tenant"] is True
    assert len(em.events) == 5


def test_bad_login_and_422(env):
    client, em, _ = env
    r = client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
    assert r.status_code == 401 and "access_token" not in r.text
    assert client.post("/api/v1/auth/login", json={}).status_code == 422
    assert client.get("/nope").status_code == 404


def test_admin_audit_forbidden_for_user_and_alg_none(env):
    client, _, _ = env
    token = _login(client, 3).json()["access_token"]  # role user
    assert client.get("/api/v1/admin/audit", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    admin = _login(client, 1).json()["access_token"]
    assert client.get("/api/v1/admin/audit", headers={"Authorization": f"Bearer {admin}"}).status_code == 200


def test_preview_errors_and_success(env, monkeypatch):
    client, em, _ = env
    h = {"Authorization": "Bearer " + _login(client).json()["access_token"]}

    async def fake_fetch(url, state, ground_truth=None):
        if url == "bad":
            raise egress.EgressError("invalid_url")
        if url == "down":
            raise egress.EgressError("connection_refused")
        return egress.FetchResult(200, "hello")

    monkeypatch.setattr("app.main.safe_fetch", fake_fetch)
    assert client.post("/api/v1/webhooks/preview", json={"url": "bad"}, headers=h).status_code == 400
    assert client.post("/api/v1/webhooks/preview", json={"url": "down"}, headers=h).status_code == 502
    ok = client.post("/api/v1/webhooks/preview", json={"url": "http://x"}, headers=h)
    assert ok.status_code == 200 and ok.json()["body"] == "hello"
    assert client.post("/api/v1/webhooks/preview", json={"url": "http://x"}).status_code == 401


def test_lab_status_and_management(env):
    client, _, db = env
    assert client.get("/api/v1/lab/status").json() == {"metadata_service": "up"}
    m = TestClient(create_management_app(db, lambda: False))
    assert m.get("/healthz").status_code == 200
    assert m.get("/internal/secret").json()["secret"] == "LAB-INTERNAL-CANARY"
    assert m.get("/readyz").json()["metadata_service"] == "down"
