"""Property 26: Detection evaluator semantics.

**Validates: Requirements 11.4, 11.5, 13.3**

Each property compares the reference evaluator to an independent oracle written
directly from the design statement (exact Fraction arithmetic, ipaddress module).
"""
import ipaddress
from fractions import Fraction

from hypothesis import given, settings, strategies as st

from labcommon.evaluator import evaluate_bola, evaluate_jwt, evaluate_ssrf
from labcommon.schema import BolaConfig, DetectionConfig, JwtConfig, SsrfConfig

CFG = DetectionConfig.load()
WINDOW = CFG.bola.window_minutes * 60
JWT_WINDOW = CFG.jwt.hijack_window_minutes * 60
BASE = 1_700_000_000 - (1_700_000_000 % WINDOW)  # epoch-aligned grid origin


# ------------------------------------------------------------------ BOLA
@st.composite
def bola_window(draw):
    """One (user, template, window) bucket with boundary-biased shape."""
    distinct = draw(st.one_of(st.sampled_from([0, 1, 3, 4, 24, 25, 26, 27]), st.integers(0, 40)))
    extra = draw(st.integers(0, 30)) if distinct else 0
    total = distinct + extra
    if total == 0:
        total = 1 if draw(st.booleans()) else 0
    # error count: bias toward exact 0.6 boundary
    boundary = (total * 3) // 5
    bad = draw(st.one_of(
        st.sampled_from([max(boundary - 1, 0), boundary, min(boundary + 1, total)]),
        st.integers(0, total)))
    bad = min(bad, total)
    kind = draw(st.lists(st.sampled_from(["403", "404", "xt2xx"]), min_size=bad, max_size=bad))
    role = draw(st.sampled_from(["user", "admin", "batch_worker"]))
    return distinct, total, kind, role


def _build_bola_events(user, windows, anchor):
    events, expected = [], set()
    n = 0
    for w_idx, (distinct, total, kinds, role) in enumerate(windows):
        start = BASE + anchor + w_idx * WINDOW
        bad = len(kinds)
        ids = [f"inv-{w_idx}-{i}" for i in range(distinct)] if distinct else []
        for i in range(total):
            if i < bad:
                k = kinds[i]
                status, xt = {"403": (403, False), "404": (404, False), "xt2xx": (200, True)}[k]
            else:
                status, xt = (200, False)
            ev = {
                "event.id": f"e{n}", "event.dataset": "appsec.api",
                "@timestamp": start + (i * (WINDOW - 1)) / max(total, 1),
                "user.id": user, "user.roles": [role],
                "appsec.endpoint_template": "/api/invoices/{id}",
                "http.response.status_code": status,
                "appsec.authz.cross_tenant": xt,
            }
            if ids:
                ev["appsec.resource_id"] = ids[i % distinct]
            events.append(ev)
            n += 1
        ratio = Fraction(bad, total) if total else Fraction(0)
        # the 25 > 3 suppression is subsumed but is stated explicitly in the design
        if (distinct > 25 and ratio > Fraction(3, 5) and role != "batch_worker" and distinct > 3):
            expected.add((user, "/api/invoices/{id}", start))
    return events, expected


@settings(max_examples=200, deadline=None)
@given(windows=st.lists(bola_window(), min_size=1, max_size=3),
       anchor=st.sampled_from([0, 1, 59, 300, 599]),
       data=st.data())
def test_bola_flags_iff_conditions(windows, anchor, data):
    events, expected = _build_bola_events("u1", windows, anchor)
    shuffled = data.draw(st.permutations(events))
    got = {d.key for d in evaluate_bola(shuffled, CFG, anchor_offset_seconds=anchor)}
    assert got == expected


def _bola_events_exact(distinct, total, bad):
    evs = []
    for i in range(total):
        evs.append({
            "event.id": f"x{i}", "event.dataset": "appsec.api", "@timestamp": BASE + i,
            "user.id": "u", "user.roles": ["user"],
            "appsec.endpoint_template": "/t", "appsec.resource_id": f"r{i % distinct}",
            "http.response.status_code": 404 if i < bad else 200,
        })
    return evs


def test_bola_boundaries_exact():
    # 25 distinct is not flagged, 26 is (ratio satisfied)
    assert evaluate_bola(_bola_events_exact(25, 30, 30), CFG) == []
    assert len(evaluate_bola(_bola_events_exact(26, 30, 30), CFG)) == 1
    # ratio exactly 0.6 (18/30) is not flagged, 19/30 is
    assert evaluate_bola(_bola_events_exact(26, 30, 18), CFG) == []
    assert len(evaluate_bola(_bola_events_exact(26, 30, 19), CFG)) == 1


# ------------------------------------------------------------------ JWT
@st.composite
def jwt_events(draw):
    n = draw(st.integers(0, 12))
    events = []
    for i in range(n):
        ev = {"event.id": f"j{i}", "event.dataset": "appsec.api",
              "@timestamp": BASE + draw(st.sampled_from(
                  [0, 1, 150, 299, 300, 301, 600, 900, draw(st.integers(0, 1200))]))}
        if draw(st.booleans()):
            ev["appsec.jwt.jti"] = draw(st.sampled_from(["jtiA", "jtiB"]))
            ev["appsec.client_pair"] = draw(st.sampled_from(["p1", "p2", "p3"]))
        alg = draw(st.sampled_from([None, "none", "HS256"]))
        if alg:
            ev["appsec.jwt.alg"] = alg
        events.append(ev)
    return events


@settings(max_examples=200, deadline=None)
@given(events=jwt_events())
def test_jwt_semantics(events):
    dets = evaluate_jwt(events, CFG)

    got_none = {d.key[0] for d in dets if d.rule == "alg_none"}
    assert got_none == {e["event.id"] for e in events if e.get("appsec.jwt.alg") == "none"}

    by_jti = {}
    for e in events:
        if "appsec.jwt.jti" in e:
            by_jti.setdefault(e["appsec.jwt.jti"], []).append(e)
    expected = set()
    for jti, evs in by_jti.items():
        if any(a["appsec.client_pair"] != b["appsec.client_pair"]
               and abs(a["@timestamp"] - b["@timestamp"]) <= JWT_WINDOW
               for a in evs for b in evs):
            expected.add(jti)
    got = [d.key[0] for d in dets if d.rule == "jti_multi_client"]
    assert len(got) == len(set(got))
    assert set(got) == expected


def test_jwt_window_boundary():
    def mk(dt):
        return [
            {"event.id": "a", "@timestamp": BASE, "appsec.jwt.jti": "j", "appsec.client_pair": "p1"},
            {"event.id": "b", "@timestamp": BASE + dt, "appsec.jwt.jti": "j", "appsec.client_pair": "p2"},
        ]
    assert len(evaluate_jwt(mk(300), CFG)) == 1
    assert evaluate_jwt(mk(301), CFG) == []
    # same pair repeated is never a hijack
    same = [dict(e, **{"appsec.client_pair": "p1"}) for e in mk(10)]
    assert evaluate_jwt(same, CFG) == []


# ------------------------------------------------------------------ SSRF
INTERNAL_NETS = [ipaddress.ip_network(c) for c in CFG.ssrf.internal_cidrs]
HOSTS = {h.lower() for h in CFG.ssrf.internal_hostnames}

_rand_ip = st.integers(0, 2**32 - 1).map(lambda i: str(ipaddress.IPv4Address(i)))
_int_ip = st.sampled_from(INTERNAL_NETS).flatmap(
    lambda n: st.integers(0, n.num_addresses - 1).map(lambda i: str(n[i])))
_edge_ip = st.sampled_from(["9.255.255.255", "10.0.0.0", "172.15.255.255", "172.16.0.0",
                            "172.31.255.255", "172.32.0.0", "192.168.255.255", "192.169.0.0",
                            "169.254.169.254", "169.253.0.1", "127.0.0.1", "128.0.0.1"])
ips = st.one_of(st.none(), _rand_ip, _int_ip, _edge_ip)
domains = st.one_of(
    st.none(),
    st.sampled_from(sorted(HOSTS) + [h.upper() for h in sorted(HOSTS)[:2]]
                    + ["example.com", "api.example.org"]))
allow_pool = ["example.com", "localhost", "10.0.0.5", "169.254.169.254", "gateway"]


@settings(max_examples=200, deadline=None)
@given(specs=st.lists(st.tuples(ips, domains, st.sampled_from(["appsec.egress", "appsec.api"])),
                      max_size=15),
       allowed=st.lists(st.sampled_from(allow_pool), max_size=3, unique=True))
def test_ssrf_semantics(specs, allowed):
    cfg = DetectionConfig(CFG.bola, CFG.jwt, SsrfConfig(
        CFG.ssrf.internal_cidrs, CFG.ssrf.internal_hostnames, tuple(allowed)))
    events, expected = [], set()
    for i, (ip, dom, ds) in enumerate(specs):
        ev = {"event.id": f"s{i}", "event.dataset": ds}
        if ip:
            ev["destination.ip"] = ip
        if dom:
            ev["destination.domain"] = dom
        events.append(ev)
        internal = (ip is not None and any(ipaddress.ip_address(ip) in n for n in INTERNAL_NETS)) \
            or (dom is not None and dom.lower() in HOSTS)
        is_allowed = (ip in allowed) or (dom is not None and dom.lower() in allowed)
        if ds == "appsec.egress" and internal and not is_allowed:
            expected.add(f"s{i}")
    got = [d.key[0] for d in evaluate_ssrf(events, cfg)]
    assert len(got) == len(set(got))
    assert set(got) == expected
