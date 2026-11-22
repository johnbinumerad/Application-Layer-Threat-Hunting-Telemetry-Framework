"""Unit tests for app.telemetry (middleware + emitter)."""
import io
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.telemetry import (TelemetryEmitter, TelemetryMiddleware, encode_otlp_logs,
                           stdout_safe)


class ListEmitter:
    def __init__(self):
        self.events = []

    def emit(self, attrs):
        self.events.append(dict(attrs))


def make_app(emitter):
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware, emitter=emitter)

    @app.get("/api/v1/invoices/{invoice_id}")
    def invoice(invoice_id: int):
        return {"id": invoice_id}

    @app.post("/api/v1/auth/login")
    def login(payload: dict):
        return {"ok": True}

    @app.get("/boom")
    def boom():
        raise RuntimeError("x")

    return app


def test_one_event_per_request_with_template_and_resource():
    em = ListEmitter()
    c = TestClient(make_app(em))
    r = c.get("/api/v1/invoices/1011", headers={
        "x-request-id": "T1", "x-lab-client-ip": "198.51.100.77",
        "user-agent": "u" * 600, "x-lab-label": "attack", "x-lab-scenario": "bola",
        "authorization": "Bearer abc.def.ghi"})
    assert r.status_code == 200
    assert len(em.events) == 1
    e = em.events[0]
    assert e["trace.id"] == "T1"
    assert e["source.ip"] == "198.51.100.77"
    assert e["appsec.endpoint_template"] == "/api/v1/invoices/{invoice_id}"
    assert e["appsec.resource_id"] == "1011"
    assert len(e["user_agent.original"]) == 512
    assert e["lab.ground_truth.label"] == "attack"
    assert e["http.request.headers.authorization"] == "Bearer abc.def.ghi"


def test_unmatched_generated_trace_and_500():
    em = ListEmitter()
    c = TestClient(make_app(em), raise_server_exceptions=False)
    assert c.get("/nope").status_code == 404
    assert c.get("/boom").status_code == 500
    assert [e["http.response.status_code"] for e in em.events] == [404, 500]
    assert em.events[0]["appsec.endpoint_template"] == "unmatched"
    assert "appsec.resource_id" not in em.events[0]
    assert len(em.events[0]["trace.id"]) == 36
    assert em.events[1]["event.outcome"] == "failure"


def test_login_password_forwarded_but_not_in_stdout_copy():
    em = ListEmitter()
    c = TestClient(make_app(em))
    c.post("/api/v1/auth/login", json={"username": "a", "password": "s3cret"})
    e = em.events[0]
    assert e["appsec.credentials.password"] == "s3cret"
    assert e["event.action"] == "auth_login"
    assert "s3cret" not in json.dumps(stdout_safe(e))


def test_emitter_drops_oldest_and_counts_on_failure():
    def handler(request):
        return httpx.Response(500)

    buf = io.StringIO()
    em = TelemetryEmitter("http://x:4318", max_queue=2, batch_size=10, stdout=buf,
                          client=httpx.Client(transport=httpx.MockTransport(handler)),
                          start_worker=False)
    for i in range(3):
        em.emit({"@timestamp": "2025-01-15T10:22:31.482Z", "n": i,
                 "http.request.headers.authorization": "Bearer z"})
    assert em.telemetry_dropped_total == 1
    em.flush()
    assert em.telemetry_dropped_total == 3
    assert "Bearer" not in buf.getvalue()


def test_otlp_encoding_types():
    body = encode_otlp_logs([{"@timestamp": "2025-01-15T10:22:31.482Z", "a": 1, "b": True,
                              "c": "x", "d": ["p"]}])
    rec = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    kv = {a["key"]: a["value"] for a in rec["attributes"]}
    assert kv["a"] == {"intValue": "1"} and kv["b"] == {"boolValue": True}
    assert kv["d"]["arrayValue"]["values"] == [{"stringValue": "p"}]
    assert rec["timeUnixNano"] == "1736936551482000000"
