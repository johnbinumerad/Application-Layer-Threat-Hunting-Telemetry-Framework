"""Target_API: deliberately vulnerable FastAPI service plus the management app.

Public app (:8000, wrapped by ``TelemetryMiddleware``):

* ``POST /api/v1/auth/login``            - issues an HS256 JWT
* ``GET  /api/v1/invoices/{invoice_id}`` - BOLA: no tenant ownership check
* ``POST /api/v1/webhooks/preview``      - SSRF: no destination filtering
* ``GET  /api/v1/admin/audit``           - accepts ``alg=none`` tokens
* ``GET  /api/v1/lab/status``            - ``metadata_service: up|down``

Management app (:8001, no middleware): ``/healthz``, ``/readyz``, ``/internal/secret``.

Handlers pass data to the telemetry middleware through ``scope["state"]`` (see the
contract in ``app.telemetry``). Error responses are generic and never include secrets.
"""
from __future__ import annotations

import asyncio
import http.client
import os
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import auth
from app.db import Database
from app.egress import EgressError, safe_fetch
from app.seed import seed
from app.telemetry import TelemetryEmitter, TelemetryMiddleware
from labcommon.schema import AuthResult, GroundTruth

METADATA_ADDR = ("169.254.169.254", 80)
INTERNAL_CANARY = "LAB-INTERNAL-CANARY"
AUDIT_LIMIT = 50

_GENERIC = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    422: "invalid_request",
    500: "internal_error",
    502: "bad_gateway",
}


def _err(status: int, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": _GENERIC.get(status, "error"), **extra}, status_code=status)


class LoginBody(BaseModel):
    username: str
    password: str


class PreviewBody(BaseModel):
    url: str


def probe_metadata_service(timeout: float = 0.5) -> bool:
    """True if the simulated metadata service answers the credentials path with the canary."""
    try:
        conn = http.client.HTTPConnection(*METADATA_ADDR, timeout=timeout)
        try:
            conn.request("GET", "/latest/meta-data/iam/security-credentials/lab-role")
            resp = conn.getresponse()
            return resp.status == 200 and b"LAB-METADATA-CANARY" in resp.read(65536)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        return False


def _state(request: Request) -> dict:
    return request.scope.setdefault("state", {})


def _ground_truth(request: Request) -> GroundTruth:
    h = request.headers
    return GroundTruth(label=h.get("x-lab-label"), scenario=h.get("x-lab-scenario"),
                       technique=h.get("x-lab-technique"), run_id=h.get("x-lab-run-id"),
                       role=h.get("x-lab-role"))


def _record_auth(request: Request, result: AuthResult) -> dict:
    """Publish the auth result and caller identity to the telemetry state."""
    state = _state(request)
    state["auth"] = result
    claims = result.claims or {}
    if claims.get("sub"):
        state["user_id"] = claims.get("sub")
    if claims.get("tenant_id"):
        state["tenant_id"] = claims.get("tenant_id")
    if claims.get("role"):
        state["roles"] = [claims["role"]]
    return state


def create_app(db: Optional[Database] = None,
               emitter: Optional[TelemetryEmitter] = None,
               metadata_probe: Callable[[], bool] = probe_metadata_service) -> FastAPI:
    """Build the public Target_API app. ``db`` defaults to a freshly seeded store."""
    if db is None:
        db = Database(os.environ.get("LAB_DB_PATH", ":memory:"))
    seed(db)

    api = FastAPI(title="Lab Target API", docs_url=None, redoc_url=None, openapi_url=None)
    api.state.db = db
    api.add_middleware(TelemetryMiddleware, emitter=emitter)

    # ---------------------------------------------------------- generic errors
    @api.exception_handler(StarletteHTTPException)
    async def _http_exc(_: Request, exc: StarletteHTTPException):
        return _err(exc.status_code)

    @api.exception_handler(RequestValidationError)
    async def _validation_exc(_: Request, __: RequestValidationError):
        return _err(422)

    @api.exception_handler(Exception)
    async def _unhandled(_: Request, __: Exception):
        return _err(500)

    # ---------------------------------------------------------------- routes
    @api.post("/api/v1/auth/login")
    async def login(body: LoginBody, request: Request):
        state = _state(request)
        state["action"] = "auth_login"
        state["password"] = body.password
        user = db.authenticate(body.username, body.password)
        if user is None:
            return _err(401)
        state["user_id"] = user["id"]
        state["tenant_id"] = user["tenant_id"]
        state["roles"] = [user["role"]]
        return {"access_token": auth.issue_token(user), "token_type": "bearer",
                "expires_in": auth.TOKEN_TTL_SECONDS}

    @api.get("/api/v1/invoices/{invoice_id}")
    async def get_invoice(invoice_id: int, request: Request):
        result = auth.validate(request.headers.get("authorization"), "invoices")
        state = _record_auth(request, result)
        if not result.accepted:
            return _err(401)
        invoice = db.get_invoice(invoice_id)
        if invoice is None:
            return _err(404)
        # BOLA (intentional): the caller's tenant is never compared to the owner's
        # for access control; only recorded for telemetry.
        state["resource_tenant_id"] = invoice["tenant_id"]
        state["cross_tenant"] = invoice["tenant_id"] != (result.claims or {}).get("tenant_id")
        return invoice

    @api.post("/api/v1/webhooks/preview")
    async def preview(body: PreviewBody, request: Request):
        result = auth.validate(request.headers.get("authorization"), "preview")
        state = _record_auth(request, result)
        if not result.accepted:
            return _err(401)
        route = request.scope.get("route")
        state["endpoint_template"] = getattr(route, "path", "/api/v1/webhooks/preview")
        try:
            fetched = await safe_fetch(body.url, state, ground_truth=_ground_truth(request))
        except EgressError as exc:
            return _err(400 if exc.error_type == "invalid_url" else 502,
                        reason=exc.error_type)
        return {"status_code": fetched.status_code, "body": fetched.body}

    @api.get("/api/v1/admin/audit")
    async def admin_audit(request: Request):
        result = auth.validate(request.headers.get("authorization"), "admin_audit")
        _record_auth(request, result)
        if not result.accepted:
            return _err(401)
        # Unsigned claims (alg=none) are trusted here by design, including ``role``.
        if (result.claims or {}).get("role") != "admin":
            return _err(403)
        return {"entries": db.recent_audit(AUDIT_LIMIT)}

    @api.get("/api/v1/lab/status")
    async def lab_status():
        up = await asyncio.get_running_loop().run_in_executor(None, metadata_probe)
        return {"metadata_service": "up" if up else "down"}

    return api


def create_management_app(db: Database,
                          metadata_probe: Callable[[], bool] = probe_metadata_service) -> FastAPI:
    """Management app: no telemetry middleware, no auth."""
    mgmt = FastAPI(title="Lab Management", docs_url=None, redoc_url=None, openapi_url=None)

    @mgmt.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @mgmt.get("/readyz")
    async def readyz():
        try:
            ready = db.count("tenants") > 0
        except Exception:
            ready = False
        up = await asyncio.get_running_loop().run_in_executor(None, metadata_probe)
        body = {"status": "ready" if ready else "not_ready",
                "metadata_service": "up" if up else "down"}
        return JSONResponse(body, status_code=200 if ready else 503)

    @mgmt.get("/internal/secret")
    async def internal_secret():
        return {"secret": INTERNAL_CANARY}

    return mgmt


def build() -> tuple[FastAPI, FastAPI]:
    """Create the public and management apps sharing one seeded database."""
    db = Database(os.environ.get("LAB_DB_PATH", ":memory:"))
    seed(db)
    db.add_audit(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
                 "system", None, "lab_startup", "seeded")
    return create_app(db), create_management_app(db)


async def serve() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    from app import metadata_sim

    # Best effort: if the address/port is unavailable, status/readyz report "down".
    metadata_sim.start_in_thread()
    public, mgmt = build()
    host = os.environ.get("LAB_BIND_HOST", "0.0.0.0")
    servers = [
        uvicorn.Server(uvicorn.Config(public, host=host, port=8000, log_level="warning")),
        uvicorn.Server(uvicorn.Config(mgmt, host=host, port=8001, log_level="warning")),
    ]
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(serve())
