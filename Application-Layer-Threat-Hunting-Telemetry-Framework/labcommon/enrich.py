"""IP to ASN/geo enrichment (Req 7.4).

Longest-prefix-match lookup against ``config/ip_enrichment.yaml`` plus a helper
that renders the same table for the painless script in the ingest pipeline.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

DEFAULT_TABLE_PATH = Path(__file__).resolve().parent.parent / "config" / "ip_enrichment.yaml"


@dataclass(frozen=True)
class Enrichment:
    asn: int
    organization: str
    country: str
    cidr: str = ""

    def as_fields(self) -> dict[str, Any]:
        """Flat ECS fields set by the ingest pipeline."""
        return {
            "source.as.number": self.asn,
            "source.as.organization.name": self.organization,
            "source.geo.country_iso_code": self.country,
        }


@dataclass(frozen=True)
class _Entry:
    network: ipaddress.IPv4Network
    enrichment: Enrichment


class EnrichmentTable:
    def __init__(self, entries: Iterable[Mapping[str, Any]]):
        parsed = []
        for e in entries:
            net = ipaddress.ip_network(str(e["cidr"]), strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError(f"only IPv4 CIDRs are supported: {e['cidr']}")
            parsed.append(
                _Entry(
                    net,
                    Enrichment(int(e["asn"]), str(e["organization"]), str(e["country"]), str(net)),
                )
            )
        # Longest prefix first; stable for ties.
        self._entries = sorted(parsed, key=lambda x: -x.network.prefixlen)

    @property
    def entries(self) -> list[_Entry]:
        return list(self._entries)

    def lookup(self, ip: str) -> Enrichment | None:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return None
        if not isinstance(addr, ipaddress.IPv4Address):
            return None
        for e in self._entries:
            if addr in e.network:
                return e.enrichment
        return None

    def painless_table(self) -> list[dict[str, Any]]:
        """Rows ``{start, end, prefix, asn, org, country}`` (integers for the range).

        Rows are ordered longest prefix first, so a painless loop that returns on
        the first containing row implements longest-prefix-match.
        """
        return [
            {
                "start": int(e.network.network_address),
                "end": int(e.network.broadcast_address),
                "prefix": e.network.prefixlen,
                "asn": e.enrichment.asn,
                "org": e.enrichment.organization,
                "country": e.enrichment.country,
            }
            for e in self._entries
        ]


def load_table(path: str | Path = DEFAULT_TABLE_PATH) -> EnrichmentTable:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return EnrichmentTable(data.get("networks") or [])


def lookup(ip: str, table: EnrichmentTable | None = None) -> Enrichment | None:
    return (table or load_table()).lookup(ip)


PAINLESS_SOURCE = """
def ip = ctx['source']?.get('ip');
if (ip == null) { return; }
String[] p = /\\./.split(ip);
if (p.length != 4) { return; }
long n = 0;
for (int i = 0; i < 4; i++) {
  int o;
  try { o = Integer.parseInt(p[i]); } catch (Exception e) { return; }
  if (o < 0 || o > 255) { return; }
  n = n * 256 + o;
}
for (def row : params.table) {
  if (n >= row.start && n <= row.end) {
    ctx['source'].putIfAbsent('as', new HashMap());
    ctx['source']['as']['number'] = row.asn;
    ctx['source']['as'].putIfAbsent('organization', new HashMap());
    ctx['source']['as']['organization']['name'] = row.org;
    ctx['source'].putIfAbsent('geo', new HashMap());
    ctx['source']['geo']['country_iso_code'] = row.country;
    return;
  }
}
""".strip()


def painless_script_processor(table: EnrichmentTable) -> dict[str, Any]:
    """The ``script`` processor body for the ``appsec-enrich`` ingest pipeline."""
    return {
        "script": {
            "lang": "painless",
            "source": PAINLESS_SOURCE,
            "params": {"table": table.painless_table()},
        }
    }
