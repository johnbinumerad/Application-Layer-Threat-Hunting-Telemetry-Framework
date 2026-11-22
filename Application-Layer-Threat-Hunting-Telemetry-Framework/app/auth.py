"""JWT issuance and the per-endpoint validation policy table (deliberately vulnerable).

The validation matrix is data (``POLICIES``), not scattered ``if`` statements:

============  ==========  ===============  =========  =========
endpoint      alg none    bad signature    expired    missing
============  ==========  ===============  =========  =========
invoices      reject      reject           accept     reject
preview       reject      reject           reject     reject
admin_audit   accept      reject           reject     reject
============  ==========  ===============  =========  =========

Tokens that parse but are rejected still yield an ``AuthResult`` carrying the
unverified claims (``verified=False``) so telemetry can record JTI and algorithm.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from labcommon.schema import AuthResult

TOKEN_TTL_SECONDS = 900
DEFAULT_SECRET = "lab-only-jwt-secret-change-me"


@dataclass(frozen=True)
class Policy:
    accept_alg_none: bool
    accept_expired: bool
    # Bad HS256 signatures are rejected on every endpoint; missing tokens too.


POLICIES: dict[str, Policy] = {
    "invoices": Policy(accept_alg_none=False, accept_expired=True),
    "preview": Policy(accept_alg_none=False, accept_expired=False),
    "admin_audit": Policy(accept_alg_none=True, accept_expired=False),
}


def _secret() -> bytes:
    return os.environ.get("LAB_JWT_SECRET", DEFAULT_SECRET).encode()


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _sign(signing_input: str, secret: Optional[bytes] = None) -> str:
    mac = hmac.new(secret if secret is not None else _secret(),
                   signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64e(mac)


def encode_token(claims: Mapping[str, Any], secret: Optional[bytes] = None) -> str:
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64e(json.dumps(dict(claims), separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    return f"{signing_input}.{_sign(signing_input, secret)}"


def issue_token(user: Mapping[str, Any], now: Optional[int] = None) -> str:
    """Issue an HS256 JWT for a user row (``id``, ``tenant_id``, ``role``)."""
    iat = int(time.time()) if now is None else int(now)
    return encode_token({
        "sub": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "jti": str(uuid.uuid4()),
        "iat": iat,
        "exp": iat + TOKEN_TTL_SECONDS,
    })


def login(db, username: str, password: str) -> Optional[str]:
    """Return a token for valid credentials, otherwise None (caller returns 401)."""
    user = db.authenticate(username, password)
    return issue_token(user) if user else None


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def _parse(token: str):
    """Return (header, claims, signing_input, signature) or None if unparseable."""
    segs = token.split(".")
    if len(segs) != 3:
        return None
    try:
        header = json.loads(_b64d(segs[0]))
        claims = json.loads(_b64d(segs[1]))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims, f"{segs[0]}.{segs[1]}", segs[2]


def _exp_info(claims: Mapping[str, Any], now: float):
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None, None
    try:
        dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None, None
    return dt, exp <= now


def validate(authorization: Optional[str], endpoint: str,
             now: Optional[float] = None) -> AuthResult:
    """Validate an Authorization header value under ``POLICIES[endpoint]``."""
    policy = POLICIES[endpoint]
    now = time.time() if now is None else now
    token = _extract_bearer(authorization)
    if token is None:
        return AuthResult(present=False)
    parsed = _parse(token)
    if parsed is None:
        # Present but unparseable: nothing to record, rejected.
        return AuthResult(present=True)
    header, claims, signing_input, signature = parsed
    alg = header.get("alg")
    alg = alg if isinstance(alg, str) else None
    jti = claims.get("jti")
    jti = jti if isinstance(jti, str) else None
    exp, expired = _exp_info(claims, now)

    verified = False
    if alg == "HS256":
        verified = hmac.compare_digest(_sign(signing_input), signature)
    elif alg is not None and alg.lower() == "none":
        alg = "none"

    if alg == "HS256":
        sig_ok = verified
    elif alg == "none":
        sig_ok = policy.accept_alg_none  # unsigned claims trusted (vulnerable by design)
    else:
        sig_ok = False
    exp_ok = (not expired) or policy.accept_expired
    accepted = sig_ok and exp_ok

    return AuthResult(
        present=True, alg=alg, verified=verified, claims=claims, jti=jti,
        exp=exp, expired=expired, accepted=accepted,
    )
