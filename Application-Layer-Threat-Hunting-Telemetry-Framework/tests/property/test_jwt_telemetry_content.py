"""Property 9: JWT telemetry content.

Feature: application-layer-threat-hunting-framework, Property 9

Drives the real validator (``app.auth.validate``) and the real ASGI telemetry middleware
and inspects the emitted event, for accepted and rejected tokens alike.

**Validates: Requirements 7.5, 7.6, 7.7**
"""
import asyncio
import json
import string
from datetime import datetime, timezone

from hypothesis import given, strategies as st

from app import auth
from app.telemetry import TelemetryMiddleware
from labcommon.schema import format_timestamp

NOW = 1_800_000_000
ENDPOINTS = sorted(auth.POLICIES)
jtis = st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=1, max_size=40)
ips = st.ip_addresses().map(str)


class _Capture:
    def __init__(self):
        self.events = []

    def emit(self, attrs):
        self.events.append(dict(attrs))


def _unsigned(claims, alg):
    h = auth._b64e(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = auth._b64e(json.dumps(claims).encode())
    return f"{h}.{p}."


def _bad_sig(claims):
    tok = auth.encode_token(claims)
    head, _, _ = tok.rpartition(".")
    return head + "." + auth._b64e(b"wrong-signature-bytes-wrong-sig!!")


@st.composite
def presented(draw):
    jti = draw(jtis)
    expired = draw(st.booleans())
    exp = NOW - draw(st.integers(1, 10**6)) if expired else NOW + draw(st.integers(1, 10**6))
    claims = {"sub": 1, "tenant_id": 1, "role": "user", "jti": jti, "iat": exp - 900, "exp": exp}
    kind = draw(st.sampled_from(["valid", "bad_sig", "none"]))
    if kind == "valid":
        token = auth.encode_token(claims)
    elif kind == "bad_sig":
        token = _bad_sig(claims)
    else:
        token = _unsigned(claims, draw(st.sampled_from(["none", "None", "NONE"])))
    return token, claims, kind, expired


def _run(token, endpoint, ip):
    cap = _Capture()

    async def app(scope, receive, send):
        scope["state"]["auth"] = auth.validate(f"Bearer {token}", endpoint, now=NOW)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_m):
        pass

    scope = {"type": "http", "method": "GET", "path": "/api/v1/x", "headers": [], "client": (ip, 1234)}
    asyncio.run(TelemetryMiddleware(app, emitter=cap)(scope, receive, send))
    assert len(cap.events) == 1
    return cap.events[0]


@given(p=presented(), endpoint=st.sampled_from(ENDPOINTS), ip=ips)
def test_jwt_telemetry_content(p, endpoint, ip):
    token, claims, kind, expired = p
    ev = _run(token, endpoint, ip)

    assert ev["appsec.jwt.jti"] == claims["jti"]  # plain form, accepted or rejected
    assert ev["source.ip"] == ip
    assert "event.start" in ev
    assert ev["appsec.jwt.alg"] == ("none" if kind == "none" else "HS256")
    if expired:
        assert ev["appsec.jwt.expired"] is True
        exp_dt = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        assert ev["appsec.jwt.exp"] == format_timestamp(exp_dt)
    else:
        assert ev.get("appsec.jwt.expired") in (False, None)
