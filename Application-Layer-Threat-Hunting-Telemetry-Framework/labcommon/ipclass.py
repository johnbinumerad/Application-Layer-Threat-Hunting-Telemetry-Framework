"""IP address parsing and internal/external classification.

Parses IPv4 in dotted, decimal, octal, hex (inet_aton style) and IPv6-mapped
notation to a canonical ``ipaddress.IPv4Address`` and classifies it as internal
(RFC 1918, loopback, link-local) or external. Pure logic, no I/O.
"""
from __future__ import annotations

import ipaddress
from typing import Optional, Union

INTERNAL_V4_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)
INTERNAL_V6_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("::1/128", "fe80::/10")
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _parse_component(part: str) -> Optional[int]:
    """Parse one inet_aton component: 0x/0X hex, leading-0 octal, else decimal."""
    if not part:
        return None
    try:
        if part[:2].lower() == "0x":
            digits = part[2:]
            if not digits or not all(c in "0123456789abcdefABCDEF" for c in digits):
                return None
            return int(digits, 16)
        if len(part) > 1 and part[0] == "0":
            if not all(c in "01234567" for c in part):
                return None
            return int(part, 8)
        if not all(c in "0123456789" for c in part):
            return None
        return int(part, 10)
    except ValueError:
        return None


def _parse_ipv4_legacy(text: str) -> Optional[ipaddress.IPv4Address]:
    """inet_aton-style parse: 1-4 parts, the last part fills remaining bytes."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for p in parts:
        v = _parse_component(p)
        if v is None:
            return None
        values.append(v)
    *head, last = values
    if any(v > 255 for v in head):
        return None
    if last >= 256 ** (5 - len(parts)):
        return None
    result = last
    for i, v in enumerate(head):
        result |= v << (8 * (3 - i))
    return ipaddress.IPv4Address(result)


def parse_ip(value: str) -> Optional[IPAddress]:
    """Return the canonical address for ``value`` or None if unparseable.

    IPv6-mapped addresses (``::ffff:a.b.c.d`` / ``::ffff:xxxx:xxxx``) resolve to
    the embedded IPv4 address.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text:
        return None
    if ":" in text:
        text = text.split("%", 1)[0]  # drop zone id
        # Mapped form with legacy-encoded IPv4 tail, e.g. ::ffff:0x7f.1
        head, sep, tail = text.rpartition(":")
        if "." in tail:
            v4 = _parse_ipv4_legacy(tail)
            if v4 is None:
                return None
            text = f"{head}{sep}{v4.packed[:2].hex().lstrip('0') or '0'}:" \
                   f"{v4.packed[2:].hex().lstrip('0') or '0'}"
        try:
            v6 = ipaddress.IPv6Address(text)
        except ValueError:
            return None
        return v6.ipv4_mapped or v6
    return _parse_ipv4_legacy(text)


def is_internal(value: Union[str, IPAddress]) -> bool:
    """True iff the canonical address is RFC 1918, loopback or link-local."""
    addr = parse_ip(value) if isinstance(value, str) else value
    if addr is None:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        addr = addr.ipv4_mapped or addr
    nets = INTERNAL_V4_NETWORKS if addr.version == 4 else INTERNAL_V6_NETWORKS
    return any(addr in n for n in nets)


def classify(value: str) -> Optional[str]:
    """Return ``"internal"``, ``"external"``, or None if ``value`` is not an IP."""
    addr = parse_ip(value)
    if addr is None:
        return None
    return "internal" if is_internal(addr) else "external"
