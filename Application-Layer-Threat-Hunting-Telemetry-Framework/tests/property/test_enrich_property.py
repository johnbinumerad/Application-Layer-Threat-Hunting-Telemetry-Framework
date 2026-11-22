"""Property 25: ASN and geo enrichment (pure-logic part).

**Validates: Requirements 7.4**

The ingest ``_simulate`` agreement check requires a live OpenSearch and is
covered by task 8.10. Here the painless lookup table is evaluated in Python
with the same first-containing-row semantics as ``PAINLESS_SOURCE``.
"""

from __future__ import annotations

import ipaddress

from hypothesis import given, strategies as st

from labcommon.enrich import EnrichmentTable, load_table
from simulators.hunt_02_jwt_abuse import HIJACK_SOURCE_IPS

ipv4 = st.integers(0, 2**32 - 1).map(lambda n: str(ipaddress.IPv4Address(n)))


@st.composite
def entries(draw):
    n = draw(st.integers(0, 8))
    out = []
    for _ in range(n):
        prefix = draw(st.integers(0, 32))
        base = draw(st.integers(0, 2**32 - 1))
        net = ipaddress.IPv4Network((base, prefix), strict=False)
        out.append(
            {
                "cidr": str(net),
                "asn": draw(st.integers(1, 4_294_967_295)),
                "organization": draw(st.text("abcdefXYZ-", min_size=1, max_size=8)),
                "country": draw(st.sampled_from(["US", "DE", "BR", "FR", "JP"])),
            }
        )
    return out


def _reference(raw, ip):
    """Brute-force longest-prefix match (first listed wins on exact ties)."""
    addr = ipaddress.IPv4Address(ip)
    best = None
    for e in raw:
        net = ipaddress.IPv4Network(e["cidr"])
        if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, e)
    return best[1] if best else None


def _painless_eval(rows, ip):
    n = int(ipaddress.IPv4Address(ip))
    for row in rows:
        if row["start"] <= n <= row["end"]:
            return row
    return None


@given(raw=entries(), ip=ipv4)
def test_lookup_is_longest_prefix_match(raw, ip):
    result = EnrichmentTable(raw).lookup(ip)
    expected = _reference(raw, ip)
    if expected is None:
        assert result is None
    else:
        assert (result.asn, result.organization, result.country) == (
            expected["asn"],
            expected["organization"],
            expected["country"],
        )


@given(raw=entries(), ip=ipv4)
def test_painless_table_agrees_with_lookup(raw, ip):
    table = EnrichmentTable(raw)
    result = table.lookup(ip)
    row = _painless_eval(table.painless_table(), ip)
    if result is None:
        assert row is None
    else:
        assert (row["asn"], row["org"], row["country"]) == (
            result.asn,
            result.organization,
            result.country,
        )


@given(raw=entries(), ip=ipv4)
def test_ip_inside_listed_cidr_is_always_enriched(raw, ip):
    table = EnrichmentTable(raw)
    if any(ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(e["cidr"]) for e in raw):
        assert table.lookup(ip) is not None


def test_default_hijack_source_ips_resolve_to_distinct_asns():
    table = load_table()
    results = [table.lookup(ip) for ip in HIJACK_SOURCE_IPS]
    assert all(r is not None for r in results)
    assert len({r.asn for r in results}) >= 2


def test_non_ipv4_input_yields_no_enrichment():
    table = load_table()
    for bad in ("", "not-an-ip", "2001:db8::1", "256.1.1.1"):
        assert table.lookup(bad) is None
