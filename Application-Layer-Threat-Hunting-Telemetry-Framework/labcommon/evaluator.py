"""Reference detection evaluator (pure logic, no I/O).

Evaluates the three detections over flat ECS attribute dicts (as produced by
``labcommon.schema`` builders) using thresholds from ``config/detections.yaml``
(via :class:`labcommon.schema.DetectionConfig`).

Boundary semantics (exact):
  * BOLA: ``distinct > distinct_ids_threshold`` and ``ratio > error_ratio_threshold``
    (strict), suppressed when ``distinct <= retry_suppression_max_ids``.
    Windows are 10 m tumbling, ``[start, start + window)``, anchored at
    ``anchor_offset_seconds`` past the epoch-aligned window grid.
  * JWT hijack: a jti seen from ``>= min_distinct_client_pairs`` distinct
    ``appsec.client_pair`` values within a closed span of ``hijack_window_minutes``.
  * SSRF: internal ``destination.ip`` (config CIDRs) or listed internal hostname,
    minus ``allowed_destination_hosts``.

Each evaluator returns a list of :class:`Detection`; ``evaluate`` runs all three.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fractions import Fraction
from typing import Any, Iterable, Mapping, Optional

from .ipclass import parse_ip
from .schema import DetectionConfig

Event = Mapping[str, Any]

BOLA = "bola"
JWT = "jwt"
SSRF = "ssrf"


@dataclass(frozen=True)
class Detection:
    scenario: str                       # bola | jwt | ssrf
    rule: str                           # sub-rule name
    key: tuple = ()                     # grouping key (e.g. user, endpoint, window)
    event_ids: tuple[str, ...] = ()     # contributing event ids
    details: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)


# ---------------------------------------------------------------- helpers
def parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _epoch(event: Event) -> Optional[float]:
    dt = parse_timestamp(event.get("@timestamp"))
    return None if dt is None else dt.timestamp()


def _eid(event: Event) -> str:
    return str(event.get("event.id", ""))


def _status(event: Event) -> Optional[int]:
    try:
        return int(event.get("http.response.status_code"))
    except (TypeError, ValueError):
        return None


def _is_2xx(event: Event) -> bool:
    s = _status(event)
    return s is not None and 200 <= s < 300


def _roles(event: Event) -> list[str]:
    r = event.get("user.roles")
    if r is None:
        return []
    return [r] if isinstance(r, str) else list(r)


def _is_api(event: Event) -> bool:
    return event.get("event.dataset", "appsec.api") == "appsec.api"


def _truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


# ---------------------------------------------------------------- BOLA
def bucket_start(ts: float, window_seconds: int, anchor_offset_seconds: int = 0) -> float:
    """Start of the tumbling window containing ``ts`` (window is [start, start+w))."""
    return ((ts - anchor_offset_seconds) // window_seconds) * window_seconds + anchor_offset_seconds


def evaluate_bola(events: Iterable[Event], config: Optional[DetectionConfig] = None,
                  anchor_offset_seconds: int = 0) -> list[Detection]:
    cfg = (config or DetectionConfig.load()).bola
    window = cfg.window_minutes * 60
    excluded = set(cfg.excluded_roles)
    ratio_thr = Fraction(str(cfg.error_ratio_threshold))

    buckets: dict[tuple, list[Event]] = {}
    for ev in events:
        if not _is_api(ev):
            continue
        user, tmpl = ev.get("user.id"), ev.get("appsec.endpoint_template")
        ts = _epoch(ev)
        if user is None or tmpl is None or ts is None:
            continue
        if excluded.intersection(_roles(ev)):
            continue
        key = (user, tmpl, bucket_start(ts, window, anchor_offset_seconds))
        buckets.setdefault(key, []).append(ev)

    out: list[Detection] = []
    for key, evs in sorted(buckets.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]), kv[0][2])):
        total = len(evs)
        distinct = len({str(e["appsec.resource_id"]) for e in evs
                        if e.get("appsec.resource_id") not in (None, "")})
        bad = 0
        for e in evs:
            s = _status(e)
            if s in (403, 404) or (_truthy(e.get("appsec.authz.cross_tenant")) and _is_2xx(e)):
                bad += 1
        if distinct <= cfg.retry_suppression_max_ids:
            continue
        if distinct > cfg.distinct_ids_threshold and Fraction(bad, total) > ratio_thr:
            out.append(Detection(BOLA, "bola_enumeration", key,
                                 tuple(_eid(e) for e in evs),
                                 {"distinct_ids": distinct, "total": total, "bad": bad,
                                  "ratio": bad / total}))
    return out


# ---------------------------------------------------------------- JWT
def evaluate_jwt(events: Iterable[Event], config: Optional[DetectionConfig] = None) -> list[Detection]:
    cfg = (config or DetectionConfig.load()).jwt
    out: list[Detection] = []
    by_jti: dict[str, list[tuple[float, str, str]]] = {}
    for ev in events:
        if not _is_api(ev):
            continue
        eid = _eid(ev)
        alg = ev.get("appsec.jwt.alg")
        if isinstance(alg, str) and alg.lower() == "none":
            out.append(Detection(JWT, "alg_none", (eid,), (eid,)))
        if ev.get("event.action") == "jwt_validation_failed":
            out.append(Detection(JWT, "jwt_validation_failed", (eid,), (eid,)))
        if _truthy(ev.get("appsec.jwt.expired")) and _is_2xx(ev):
            out.append(Detection(JWT, "expired_accepted", (eid,), (eid,)))
        jti, pair, ts = ev.get("appsec.jwt.jti"), ev.get("appsec.client_pair"), _epoch(ev)
        if jti and pair and ts is not None:
            by_jti.setdefault(str(jti), []).append((ts, str(pair), eid))

    window = cfg.hijack_window_minutes * 60
    for jti, items in sorted(by_jti.items()):
        items.sort()
        hit: Optional[tuple[str, ...]] = None
        lo = 0
        for hi in range(len(items)):
            while items[hi][0] - items[lo][0] > window:
                lo += 1
            span = items[lo:hi + 1]
            if len({p for _, p, _ in span}) >= cfg.min_distinct_client_pairs:
                hit = tuple(e for _, _, e in span)
                break
        if hit:
            out.append(Detection(JWT, "jti_multi_client", (jti,), hit))
    return out


# ---------------------------------------------------------------- SSRF
def _in_cidrs(ip_text: str, cidrs: Iterable[str]) -> bool:
    addr = parse_ip(ip_text)
    if addr is None:
        return False
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if addr.version == net.version and addr in net:
            return True
    return False


def evaluate_ssrf(events: Iterable[Event], config: Optional[DetectionConfig] = None) -> list[Detection]:
    cfg = (config or DetectionConfig.load()).ssrf
    hosts = {h.lower() for h in cfg.internal_hostnames}
    allowed = {h.lower() for h in cfg.allowed_destination_hosts}
    out: list[Detection] = []
    for ev in events:
        if ev.get("event.dataset") != "appsec.egress":
            continue
        ip, domain = ev.get("destination.ip"), ev.get("destination.domain")
        dom = str(domain).lower() if domain else None
        internal = bool(ip and _in_cidrs(str(ip), cfg.internal_cidrs)) or \
            bool(dom and dom in hosts)
        if not internal:
            continue
        candidates = {str(x).lower() for x in (ip, domain, ev.get("destination.address")) if x}
        if candidates & allowed:
            continue
        eid = _eid(ev)
        out.append(Detection(SSRF, "ssrf_internal_egress", (eid,), (eid,)))
    return out


# ---------------------------------------------------------------- all
def evaluate(events: Iterable[Event], config: Optional[DetectionConfig] = None,
             anchor_offset_seconds: int = 0) -> list[Detection]:
    cfg = config or DetectionConfig.load()
    evs = list(events)
    return (evaluate_bola(evs, cfg, anchor_offset_seconds)
            + evaluate_jwt(evs, cfg) + evaluate_ssrf(evs, cfg))
