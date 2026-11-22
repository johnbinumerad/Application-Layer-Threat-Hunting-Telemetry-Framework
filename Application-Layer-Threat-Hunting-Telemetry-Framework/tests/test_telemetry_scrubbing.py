"""Unit tests: stdout/log scrubbing, OTLP sensitive fields, seed counts, latency, mapping.

Validates: Requirements 2.3, 2.8, 3.8, 4.1, 4.3, 4.4
"""
import io
import json
import logging
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.main import create_app
from app.seed import TENANT_IDS, seed_users_spec
from app.telemetry import SENSITIVE_FIELDS, TelemetryEmitter

ROOT = Path(__file__).resolve().parents[1]
AUTHZ = "http.request.headers.authorization"
PWD = "appsec.credentials.password"


@pytest.fixture()
def env():
    stdout = io.StringIO()
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    em = TelemetryEmitter("http://collector:4318", stdout=stdout, client=client,
                          start_worker=False)
    db = Database(":memory:")
    api = create_app(db, em, metadata_probe=lambda: True)
    return TestClient(api, raise_server_exceptions=False), em, stdout, sent


def _otlp_attrs(sent):
    out = []
    for payload in sent:
        for rl in payload["resourceLogs"]:
            for sl in rl["scopeLogs"]:
                for rec in sl["logRecords"]:
                    out.append({a["key"]: a["value"] for a in rec["attributes"]})
    return out


def _login_and_use(client):
    u = seed_users_spec()[0]
    r = client.post("/api/v1/auth/login",
                    json={"username": u["username"], "password": u["password"]})
    token = r.json()["access_token"]
    client.get("/api/v1/invoices/1001", headers={"Authorization": f"Bearer {token}"})
    return u["password"], token


def test_stdout_and_logs_never_contain_raw_jwt_or_password(env, caplog, capsys):
    client, em, stdout, _ = env
    with caplog.at_level(logging.DEBUG):
        password, token = _login_and_use(client)
        em.flush()
    out = stdout.getvalue()
    assert out.strip(), "stdout copy should contain events"
    for line in out.strip().splitlines():
        ev = json.loads(line)
        assert not set(SENSITIVE_FIELDS) & set(ev)
    captured = capsys.readouterr()
    for text in (out, caplog.text, captured.out, captured.err):
        assert password not in text
        assert token not in text
        assert "Bearer " not in text


def test_otlp_contains_raw_values_only_in_sensitive_fields(env):
    client, em, _, sent = env
    password, token = _login_and_use(client)
    em.flush()
    records = _otlp_attrs(sent)
    assert len(records) == 2
    login_rec, invoice_rec = records
    assert login_rec[PWD]["stringValue"] == password
    assert invoice_rec[AUTHZ]["stringValue"] == f"Bearer {token}"
    for rec in records:
        for key, value in rec.items():
            if key in SENSITIVE_FIELDS:
                continue
            blob = json.dumps(value)
            assert password not in blob and token not in blob, key


def test_seed_counts():
    db = Database(":memory:")
    from app.seed import seed
    seed(db)
    tenants = db.count("tenants")
    assert 3 <= tenants <= 10
    assert db.count("invoices") >= 5 * tenants
    assert len(TENANT_IDS) == tenants


def test_invoice_latency_under_500ms(env):
    client, _, _, _ = env
    _, token = _login_and_use(client)
    h = {"Authorization": f"Bearer {token}"}
    start = time.perf_counter()
    r = client.get("/api/v1/invoices/1002", headers=h)
    assert r.status_code == 200
    assert (time.perf_counter() - start) < 0.5


def test_endpoint_template_mapped_as_keyword():
    tpl = json.loads((ROOT / "infra/opensearch/index_template.json").read_text())

    def find(node):
        if isinstance(node, dict):
            if "endpoint_template" in node:
                return node["endpoint_template"]
            for v in node.values():
                r = find(v)
                if r is not None:
                    return r
        return None

    assert find(tpl)["type"] == "keyword"
