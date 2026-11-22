"""Property 21: IP classification across encodings.

**Validates: Requirements 8.4, 12.5, 2.11**
"""
import ipaddress
from urllib.parse import urlsplit

from hypothesis import given, strategies as st

from labcommon.ipclass import classify, is_internal, parse_ip
from simulators.hunt_03_ssrf_egress import ALT_ENCODING_URLS

INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]

# Mix uniform random addresses with ones drawn from the internal ranges.
_random_v4 = st.integers(0, 2**32 - 1).map(ipaddress.IPv4Address)
_internal_v4 = st.sampled_from(INTERNAL_NETS).flatmap(
    lambda n: st.integers(0, n.num_addresses - 1).map(lambda i: n[i]))
v4 = st.one_of(_random_v4, _internal_v4)


def encodings(a: ipaddress.IPv4Address) -> list[str]:
    n = int(a)
    o = a.packed
    return [
        str(a),                                         # dotted
        str(n),                                         # decimal
        ".".join("0%o" % b if b else "0" for b in o),   # octal per octet
        "0%o" % n,                                      # octal single integer
        ".".join(hex(b) for b in o),                    # hex per octet
        hex(n),                                         # hex single integer
        f"::ffff:{a}",                                  # IPv6-mapped dotted
        f"::ffff:{o[0]:02x}{o[1]:02x}:{o[2]:02x}{o[3]:02x}",  # IPv6-mapped hex
        f"[::ffff:{a}]",                                # bracketed
    ]


@given(v4)
def test_all_encodings_resolve_to_same_canonical_and_class(addr):
    expected_internal = any(addr in n for n in INTERNAL_NETS)
    for text in encodings(addr):
        assert parse_ip(text) == addr, text
        assert is_internal(text) == expected_internal, text
        assert classify(text) == ("internal" if expected_internal else "external"), text


def test_ssrf_payload_set_has_internal_alternate_encoding():
    internal = []
    for url in ALT_ENCODING_URLS:
        host = urlsplit(url).hostname
        if host and is_internal(host):
            internal.append(url)
    assert internal
    assert len(internal) == len(ALT_ENCODING_URLS)
