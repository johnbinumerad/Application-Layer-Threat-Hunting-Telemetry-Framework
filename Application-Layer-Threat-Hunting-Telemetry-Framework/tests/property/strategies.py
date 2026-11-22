"""Shared Hypothesis strategies for property tests."""
import ipaddress

from hypothesis import strategies as st

# Lab tenants/users/invoices (see design: seed data)
tenant_ids = st.sampled_from([f"tnt_{i:03d}" for i in range(1, 6)])
invoice_ids = st.integers(min_value=1001, max_value=1050)
http_methods = st.sampled_from(["GET", "POST", "PUT", "DELETE"])
status_codes = st.sampled_from([200, 201, 301, 302, 400, 401, 403, 404, 429, 500, 503])

ipv4_addresses = st.integers(min_value=0, max_value=2**32 - 1).map(
    lambda n: ipaddress.IPv4Address(n)
)
ipv6_addresses = st.integers(min_value=0, max_value=2**128 - 1).map(
    lambda n: ipaddress.IPv6Address(n)
)

# Lab enrichment ranges (RFC 5737 documentation networks)
lab_networks = st.sampled_from(
    [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
)


@st.composite
def lab_ipv4(draw):
    net = draw(lab_networks)
    return ipaddress.IPv4Address(
        int(net.network_address) + draw(st.integers(0, net.num_addresses - 1))
    )


# Printable text without NUL for user agents etc.
user_agents = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=0, max_size=1200
)

latencies_ms = st.floats(min_value=0, max_value=60_000, allow_nan=False, allow_infinity=False)
