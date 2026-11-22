import ipaddress

from hypothesis import given, strategies as st

from labcommon.enrich import EnrichmentTable, load_table, lookup, painless_script_processor


def test_default_table_lookups():
    assert lookup("192.0.2.5").asn == 64496
    r = lookup("198.51.100.9")
    assert (r.asn, r.organization, r.country) == (64497, "LabNet-Cloud", "DE")
    assert lookup("203.0.113.200").country == "BR"
    assert lookup("10.0.0.1") is None
    assert lookup("not-an-ip") is None
    assert lookup("::1") is None


def test_longest_prefix_wins():
    t = EnrichmentTable(
        [
            {"cidr": "10.0.0.0/8", "asn": 1, "organization": "a", "country": "US"},
            {"cidr": "10.1.0.0/16", "asn": 2, "organization": "b", "country": "DE"},
        ]
    )
    assert t.lookup("10.1.2.3").asn == 2
    assert t.lookup("10.2.2.3").asn == 1


def test_painless_table_and_processor():
    t = load_table()
    proc = painless_script_processor(t)
    rows = proc["script"]["params"]["table"]
    assert len(rows) == 3
    assert rows[0]["start"] <= rows[0]["end"]


@given(st.integers(0, 2**32 - 1))
def test_lookup_matches_longest_containing_cidr(n):
    t = load_table()
    ip = str(ipaddress.IPv4Address(n))
    matches = [e for e in t.entries if ipaddress.ip_address(ip) in e.network]
    r = t.lookup(ip)
    if not matches:
        assert r is None
    else:
        best = max(matches, key=lambda e: e.network.prefixlen)
        assert r == best.enrichment
