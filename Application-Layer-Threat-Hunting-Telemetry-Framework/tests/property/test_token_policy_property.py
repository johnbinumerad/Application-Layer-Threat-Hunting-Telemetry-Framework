"""Property 3: per-endpoint token validation policy."""
import json

from fastapi.testclient import TestClient
from hypothesis import given, strategies as st

from app import auth
from app.db import Database
from app.main import create_app


class _NullEmitter:
    def emit(self, attrs):
        pass


_CLIENT = TestClient(create_app(Database(":memory:"), _NullEmitter(), metadata_probe=lambda: True),
                     raise_server_exceptions=False)

NOW = 1_800_000_000
VARIANTS = ["valid", "bad_signature", "alg_none", "expired", "missing", "malformed"]

# (endpoint name for auth.validate, HTTP method, path, json body)
ENDPOINTS = {
    "invoices": ("GET", "/api/v1/invoices/1", None),
    "preview": ("POST", "/api/v1/webhooks/preview", {"url": "notaurl"}),
    "admin_audit": ("GET", "/api/v1/admin/audit", None),
}

# Policy table from the design: variant -> accepted, per endpoint.
EXPECTED = {
    "invoices": {"valid": True, "expired": True, "bad_signature": False,
                 "alg_none": False, "missing": False, "malformed": False},
    "preview": {"valid": True, "expired": False, "bad_signature": False,
                "alg_none": False, "missing": False, "malformed": False},
    "admin_audit": {"valid": True, "expired": False, "bad_signature": False,
                    "alg_none": True, "missing": False, "malformed": False},
}

_text = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=12)
claims_st = st.fixed_dictionaries({
    "sub": _text,
    "tenant_id": _text,
    "role": st.sampled_from(["admin", "user", "viewer", "auditor"]),
    "jti": _text,
})


def _build(variant, claims, now=None):
    """Return (authorization header or None, the claims embedded in the token)."""
    now = NOW
    c = dict(claims)
    c["iat"] = now - 60
    c["exp"] = now + 600
    if variant == "expired":
        c["exp"] = now - 1
    if variant in ("valid", "expired"):
        return f"Bearer {auth.encode_token(c)}", c
    if variant == "bad_signature":
        return f"Bearer {auth.encode_token(c, secret=b'wrong-secret')}", c
    if variant == "alg_none":
        h = auth._b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        p = auth._b64e(json.dumps(c).encode())
        return f"Bearer {h}.{p}.", c
    if variant == "malformed":
        return "Bearer not.a.jwt!!", c
    return None, c  # missing


@given(st.sampled_from(VARIANTS), claims_st, st.sampled_from(sorted(ENDPOINTS)))
def test_property_3_validate_matches_policy_table(variant, claims, endpoint):
    """**Validates: Requirements 2.5, 2.10, 2.12**"""
    header, c = _build(variant, claims)
    result = auth.validate(header, endpoint, now=NOW)
    assert result.accepted == EXPECTED[endpoint][variant]
    if result.accepted and variant == "alg_none":
        assert result.claims == c  # effective identity == unsigned claims


@given(st.sampled_from(VARIANTS), claims_st, st.sampled_from(sorted(ENDPOINTS)))
def test_property_3_http_decision_matches_policy_table(variant, claims, endpoint):
    """**Validates: Requirements 2.5, 2.10, 2.12**"""
    # HTTP layer uses wall-clock time; shift the claims into the real present.
    import time
    real_now = int(time.time())
    header, c = _build(variant, claims)
    if header is not None and variant in ("valid", "expired", "bad_signature"):
        c["iat"], c["exp"] = real_now - 60, real_now + (-1 if variant == "expired" else 600)
        header = f"Bearer {auth.encode_token(c, secret=b'wrong-secret' if variant == 'bad_signature' else None)}"
    elif variant == "alg_none":
        c["iat"], c["exp"] = real_now - 60, real_now + 600
        h = auth._b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        header = f"Bearer {h}.{auth._b64e(json.dumps(c).encode())}."
    method, path, body = ENDPOINTS[endpoint]
    headers = {"Authorization": header} if header else {}
    r = _CLIENT.request(method, path, headers=headers, json=body)
    accepted = EXPECTED[endpoint][variant]
    if not accepted:
        assert r.status_code == 401
        assert r.json() == {"error": "unauthorized"}
    else:
        assert r.status_code != 401
        if endpoint == "admin_audit":
            # unsigned role is trusted: admin sees data, others forbidden
            assert (r.status_code == 200) == (c["role"] == "admin")
            if r.status_code == 403:
                assert "entries" not in r.json()
