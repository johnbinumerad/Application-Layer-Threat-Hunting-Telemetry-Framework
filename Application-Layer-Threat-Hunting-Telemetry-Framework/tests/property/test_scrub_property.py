"""Properties 11-13: scrubbing removes sensitive values, salted hash
determinism/separation, and JTI preserved in plain form.

**Validates: Requirements 4.1, 4.2, 4.3, 4.6**
"""
import json

from hypothesis import given, strategies as st

from labcommon.scrub_model import (
    AUTH_KEY,
    JTI_KEY,
    PASSWORD_KEY,
    STATUS_KEY,
    TOKEN_HASH_KEY,
    is_sealed,
    salted_hash,
    scrub_record,
)

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_seg = st.text(alphabet=_B64, min_size=8, max_size=40)
# JWT-shaped token: eyJ<hdr>.<payload>.<sig>
jwt_tokens = st.builds(lambda h, p, s: f"eyJ{h}.{p}.{s}", _seg, _seg, _seg)
salts = st.text(min_size=1, max_size=32)
# Distinctive passwords so a substring check cannot hit by coincidence.
passwords = st.text(min_size=1, max_size=40).map(lambda s: "PWD\u2603" + s)
_filler = st.text(alphabet="abcdefghij klmnop:;,=/", max_size=30)
_attr_keys = st.sampled_from(
    ["http.url", "error.message", "appsec.note", "user_agent.original", "tags"]
)


@st.composite
def sensitive_records(draw):
    auth_token = draw(jwt_tokens)
    password = draw(passwords)
    embedded = draw(st.lists(jwt_tokens, min_size=0, max_size=3))
    bearers = draw(st.lists(jwt_tokens, min_size=0, max_size=2))
    rec = {
        AUTH_KEY: "Bearer " + auth_token,
        PASSWORD_KEY: password,
        "event.id": "evt-1",
    }
    raw = [auth_token]
    for i, tok in enumerate(embedded):
        rec[f"appsec.embedded_{i}"] = f"{draw(_filler)} {tok} {draw(_filler)}"
        raw.append(tok)
    for i, tok in enumerate(bearers):
        rec[f"appsec.bearer_{i}"] = f"{draw(_filler)} Bearer {tok}"
        raw.append(tok)
    return rec, raw, password


@given(sensitive_records(), salts)
def test_property_11_scrubbing_removes_sensitive_values(data, salt):
    rec, raw_tokens, password = data
    out = scrub_record(rec, salt)
    assert is_sealed(out)
    assert PASSWORD_KEY not in out and AUTH_KEY not in out
    blob = json.dumps(out, ensure_ascii=False)
    for tok in raw_tokens:
        assert tok not in blob
    assert password not in blob
    # No password-derived mask: only input keys plus derived/status keys remain,
    # and none of the surviving values encode the password's length.
    assert set(out) <= set(rec) | {TOKEN_HASH_KEY, STATUS_KEY}
    assert out[TOKEN_HASH_KEY] == salted_hash(salt, raw_tokens[0])


@given(jwt_tokens, jwt_tokens, salts, salts)
def test_property_12_salted_hash_determinism_and_separation(t1, t2, s1, s2):
    def h(tok, salt):
        return scrub_record({AUTH_KEY: "Bearer " + tok}, salt)[TOKEN_HASH_KEY]

    assert h(t1, s1) == h(t1, s1)
    if t1 == t2:
        assert h(t1, s1) == h(t2, s1)
    else:
        assert h(t1, s1) != h(t2, s1)
    if s1 != s2:
        assert h(t1, s1) != h(t1, s2)


_jti = st.one_of(
    st.text(max_size=60),
    jwt_tokens,
    st.text(alphabet="0123456789abcdef", min_size=16, max_size=64),
    st.builds(lambda t: "Bearer " + t, jwt_tokens),
)


@given(_jti, salts)
def test_property_13_jti_preserved_in_plain_form(jti, salt):
    out = scrub_record({JTI_KEY: jti, "event.id": "e"}, salt)
    assert out[JTI_KEY] == jti
