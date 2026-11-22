"""Telemetry for the Target_API: pure ASGI middleware and OTLP/HTTP log emitter.

Handler -> middleware contract
------------------------------
Handlers and ``app.auth`` communicate with the middleware through the per-request
state dict (``request.state.<name>``, which is ``scope["state"]``). All keys are
optional; unavailable data is simply omitted from the event.

    trace_id            set by the middleware (use it for Egress_Events)
    auth                ``labcommon.schema.AuthResult`` (also for rejected tokens)
    action              ``api_request`` | ``auth_login`` | ``jwt_validation_failed``
    user_id, tenant_id  caller identity (fallback: ``sub`` / ``tenant_id`` claims)
    roles               list of roles (fallback: ``role`` claim)
    resource_tenant_id  tenant owning the requested resource
    cross_tenant        bool, resource owner differs from the caller
    egress_count        number of outbound requests made while serving the request
    password            login password (fallback: ``password`` in a JSON login body)

Deliberately, the raw ``Authorization`` header and the login password are sent to the
Collector (``http.request.headers.authorization`` / ``appsec.credentials.password``)
so that scrubbing is a real pipeline control. They never reach the stdout copy.
"""
from __future__ import annotations

import collections
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, TextIO

import httpx

from labcommon.schema import AuthResult, GroundTruth, TelemetryEvent

SENSITIVE_FIELDS = (
    "http.request.headers.authorization",
    "appsec.credentials.password",
)
LOGIN_PATH = "/api/v1/auth/login"
UNMATCHED = "unmatched"
DEFAULT_OTLP_ENDPOINT = "http://otel-collector:4318"
MAX_BODY_CAPTURE = 64 * 1024


# ------------------------------------------------------------------ OTLP encoding
def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [_any_value(v) for v in value]}}
    return {"stringValue": str(value)}


def encode_otlp_logs(records: Iterable[Mapping[str, Any]],
                     service_name: str = "target-api") -> dict[str, Any]:
    """Encode flat attribute dicts as an OTLP/HTTP JSON ``ExportLogsServiceRequest``."""
    log_records = []
    for attrs in records:
        ts = attrs.get("@timestamp")
        try:
            dt = datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            nanos = int(dt.timestamp() * 1000) * 1_000_000
        except (TypeError, ValueError):
            nanos = time.time_ns()
        log_records.append({
            "timeUnixNano": str(nanos),
            "observedTimeUnixNano": str(time.time_ns()),
            "severityNumber": 9,
            "severityText": "INFO",
            "body": {"stringValue": ""},
            "attributes": [{"key": k, "value": _any_value(v)}
                           for k, v in attrs.items() if k != "@timestamp"],
        })
    return {"resourceLogs": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": service_name}}]},
        "scopeLogs": [{"scope": {"name": "app.telemetry"}, "logRecords": log_records}],
    }]}


def stdout_safe(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """Copy of an event without any Sensitive_Field."""
    return {k: v for k, v in attrs.items() if k not in SENSITIVE_FIELDS}


# ------------------------------------------------------------------ emitter
class TelemetryEmitter:
    """Non-blocking emitter: bounded drop-oldest queue, background OTLP/HTTP batch sender.

    ``emit`` never raises and never blocks on the network. Export failures increment
    ``telemetry_dropped_total`` by the size of the lost batch.
    """

    def __init__(self, endpoint: Optional[str] = None, *, max_queue: int = 2048,
                 batch_size: int = 256, flush_interval: float = 1.0,
                 export_timeout: float = 5.0, stdout: Optional[TextIO] = None,
                 client: Optional[httpx.Client] = None, start_worker: bool = True) -> None:
        base = (endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
                or DEFAULT_OTLP_ENDPOINT).rstrip("/")
        self.url = base if base.endswith("/v1/logs") else base + "/v1/logs"
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.stdout = stdout
        self._max_queue = max_queue
        self._queue: collections.deque = collections.deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._dropped = 0
        self._client = client or httpx.Client(timeout=export_timeout)
        self._thread: Optional[threading.Thread] = None
        if start_worker:
            self._thread = threading.Thread(target=self._run, name="otlp-emitter", daemon=True)
            self._thread.start()

    @property
    def telemetry_dropped_total(self) -> int:
        return self._dropped

    def emit(self, attrs: Mapping[str, Any]) -> None:
        try:
            if self.stdout is not None:
                self.stdout.write(json.dumps(stdout_safe(attrs), default=str) + "\n")
                self.stdout.flush()
        except Exception:
            pass
        with self._lock:
            if len(self._queue) >= self._max_queue:
                self._queue.popleft()
                self._dropped += 1
            self._queue.append(dict(attrs))
            should_wake = len(self._queue) >= self.batch_size
        if should_wake:
            self._wake.set()

    def _take(self) -> list[dict[str, Any]]:
        with self._lock:
            n = min(self.batch_size, len(self._queue))
            return [self._queue.popleft() for _ in range(n)]

    def _send(self, batch: list[dict[str, Any]]) -> None:
        try:
            resp = self._client.post(self.url, json=encode_otlp_logs(batch))
            if resp.status_code >= 300:
                raise RuntimeError(f"collector returned {resp.status_code}")
        except Exception:
            with self._lock:
                self._dropped += len(batch)

    def flush(self) -> None:
        """Synchronously send everything queued (used by tests and shutdown)."""
        while True:
            batch = self._take()
            if not batch:
                return
            self._send(batch)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            try:
                self.flush()
            except Exception:
                pass

    def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            self.flush()
        finally:
            self._client.close()


_emitter: Optional[TelemetryEmitter] = None
_emitter_lock = threading.Lock()


def get_emitter() -> TelemetryEmitter:
    """Process-wide emitter (created lazily; stdout JSON copy enabled)."""
    global _emitter
    with _emitter_lock:
        if _emitter is None:
            _emitter = TelemetryEmitter(stdout=sys.stdout)
        return _emitter


def set_emitter(emitter: Optional[TelemetryEmitter]) -> None:
    global _emitter
    with _emitter_lock:
        _emitter = emitter


def emit_event(attrs: Mapping[str, Any]) -> None:
    """Emit a prepared attribute dict (used by egress.py for Egress_Events)."""
    try:
        get_emitter().emit(attrs)
    except Exception:
        pass


# ------------------------------------------------------------------ middleware
def _headers(scope: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in scope.get("headers") or []:
        out.setdefault(k.decode("latin-1").lower(), v.decode("latin-1"))
    return out


def _first_path_param(scope: Mapping[str, Any]) -> Optional[str]:
    params = scope.get("path_params") or {}
    for value in params.values():
        return str(value)
    return None


class TelemetryMiddleware:
    """Pure ASGI middleware: exactly one ``appsec.api`` event per HTTP request."""

    def __init__(self, app: Callable, emitter: Optional[TelemetryEmitter] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.app = app
        self._emitter = emitter
        self._clock = clock

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        start = self._clock()
        t0 = time.perf_counter_ns()
        headers = _headers(scope)
        trace_id = headers.get("x-request-id") or str(uuid.uuid4())
        client = scope.get("client")
        source_ip = headers.get("x-lab-client-ip") or (client[0] if client else "0.0.0.0")
        state = scope.setdefault("state", {})
        state["trace_id"] = trace_id
        state["source_ip"] = source_ip

        status = {"code": None}
        body = bytearray()
        capture_body = scope.get("method") == "POST" and scope.get("path") == LOGIN_PATH

        async def recv():
            message = await receive()
            if capture_body and message.get("type") == "http.request":
                if len(body) < MAX_BODY_CAPTURE:
                    body.extend(message.get("body", b"")[: MAX_BODY_CAPTURE - len(body)])
            return message

        async def snd(message):
            if message.get("type") == "http.response.start":
                status["code"] = int(message["status"])
            await send(message)

        try:
            await self.app(scope, recv if capture_body else receive, snd)
        except BaseException:
            if status["code"] is None:
                status["code"] = 500
            raise
        finally:
            try:
                self._record(scope, headers, state, trace_id, source_ip, start, t0,
                             status["code"] if status["code"] is not None else 500,
                             bytes(body))
            except Exception:
                pass  # telemetry must never fail a request

    # -------------------------------------------------------------- event building
    def _record(self, scope, headers, state, trace_id, source_ip, start, t0, status, body):
        duration_ns = time.perf_counter_ns() - t0
        route = scope.get("route")
        route_path = getattr(route, "path", None)
        template = route_path if route_path else UNMATCHED
        resource_id = _first_path_param(scope) if route_path else None

        auth = state.get("auth")
        claims = auth.claims if isinstance(auth, AuthResult) else {}
        user_id = state.get("user_id") or claims.get("sub")
        tenant_id = state.get("tenant_id") or claims.get("tenant_id")
        roles = state.get("roles")
        if roles is None:
            roles = [claims["role"]] if claims.get("role") else []

        action = state.get("action")
        if not action:
            if scope.get("path") == LOGIN_PATH:
                action = "auth_login"
            elif isinstance(auth, AuthResult) and auth.present and not auth.accepted:
                action = "jwt_validation_failed"
            else:
                action = "api_request"

        has_auth = isinstance(auth, AuthResult) and auth.present
        event = TelemetryEvent(
            trace_id=trace_id,
            source_ip=source_ip,
            start=start,
            duration_ns=duration_ns,
            action=action,
            outcome="success" if status < 400 else "failure",
            method=scope.get("method", ""),
            status_code=status,
            path=scope.get("path", ""),
            endpoint_template=template,
            egress_count=int(state.get("egress_count") or 0),
            user_agent=headers.get("user-agent"),
            user_id=user_id,
            user_roles=roles,
            tenant_id=tenant_id,
            resource_id=resource_id,
            jwt_jti=auth.jti if has_auth else None,
            jwt_alg=auth.alg if has_auth else None,
            jwt_exp=auth.exp if has_auth else None,
            jwt_expired=auth.expired if has_auth else None,
            jwt_verified=auth.verified if has_auth else None,
            resource_tenant_id=state.get("resource_tenant_id"),
            cross_tenant=state.get("cross_tenant"),
            ground_truth=GroundTruth(
                label=headers.get("x-lab-label"),
                scenario=headers.get("x-lab-scenario"),
                technique=headers.get("x-lab-technique"),
                run_id=headers.get("x-lab-run-id"),
                role=headers.get("x-lab-role"),
            ),
        )
        attrs = event.to_attributes()

        authz = headers.get("authorization")
        if authz:
            attrs["http.request.headers.authorization"] = authz
        password = state.get("password")
        if password is None and body:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and isinstance(parsed.get("password"), str):
                    password = parsed["password"]
            except ValueError:
                pass
        if password:
            attrs["appsec.credentials.password"] = password

        (self._emitter or get_emitter()).emit(attrs)
