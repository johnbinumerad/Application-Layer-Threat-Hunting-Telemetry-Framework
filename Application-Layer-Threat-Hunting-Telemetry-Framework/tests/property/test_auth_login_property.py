"""Property tests for token issuance (Property 1) and invalid credentials (Property 2)."""
from fastapi.testclient import TestClient
from hypothesis import given, strategies as st

from app import auth
from app.db import Database
from app.main import create_app
from app.seed import seed_users_spec

USERS = seed_users_spec()
VALID_PAIRS = {(u["username"], u["password"]) for u in USERS}


class _NullEmitter:
    def emit(self, attrs):
        pass


_CLIENT = TestClient(create_app(Database(":memory:"), _NullEmitter(), metadata_probe=lambda: True),
                     raise_server_exceptions=False)
_LOGIN = "/api/v1/auth/login"


def _claims(token: str) -> dict:
    parsed = auth._parse(token)
    assert parsed is not None
    return parsed[1]


# Feature: application-layer-threat-hunting-framework, Property 1: Token issuance
# **Validates: Requirements 2.1**
@given(st.lists(st.integers(min_value=0, max_value=len(USERS) - 1), min_size=1, max_size=15))
def test_property_1_token_issuance(indices):
    jtis = set()
    for i in indices:
        u = USERS[i]
        r = _CLIENT.post(_LOGIN, json={"username": u["username"], "password": u["password"]})
        assert r.status_code == 200
        token = r.json()["access_token"]
        c = _claims(token)
        assert c["exp"] - c["iat"] == 900
        assert (c["sub"], c["tenant_id"], c["role"]) == (u["id"], u["tenant_id"], u["role"])
        assert c["jti"] not in jtis
        jtis.add(c["jti"])
    assert len(jtis) == len(indices)


# Feature: application-layer-threat-hunting-framework, Property 2: Invalid credentials issue no token
# **Validates: Requirements 2.2**
@given(st.text(max_size=40), st.text(max_size=40))
def test_property_2_non_matching_credentials(username, password):
    if (username, password) in VALID_PAIRS:
        return
    r = _CLIENT.post(_LOGIN, json={"username": username, "password": password})
    assert r.status_code == 401
    assert "access_token" not in r.text


@given(st.sampled_from(USERS), st.text(max_size=40))
def test_property_2_wrong_password_for_real_user(user, password):
    if password == user["password"]:
        return
    r = _CLIENT.post(_LOGIN, json={"username": user["username"], "password": password})
    assert r.status_code == 401
    assert "access_token" not in r.text


@given(
    st.dictionaries(st.sampled_from(["username", "password"]), st.text(max_size=40), max_size=1),
    st.sampled_from(USERS),
)
def test_property_2_missing_field(partial, user):
    body = dict(partial)
    if "username" in body:
        body["username"] = user["username"]
    if "password" in body:
        body["password"] = user["password"]
    r = _CLIENT.post(_LOGIN, json=body)
    assert 400 <= r.status_code < 500
    assert "access_token" not in r.text
