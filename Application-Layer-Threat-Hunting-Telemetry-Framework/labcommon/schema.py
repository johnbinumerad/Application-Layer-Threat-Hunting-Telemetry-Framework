"""Shared telemetry schema: ECS-named event builders and small models.

Builders produce the *flat* ECS attribute dict (dotted keys) described in
``config/field_mapping.yaml``. Unavailable fields are omitted, never emitted as
empty strings.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import yaml

USER_AGENT_MAX = 512
DATASET_API = "appsec.api"
DATASET_EGRESS = "appsec.egress"
DATASET_GATEWAY = "appsec.gateway"

_REPO_ROOT = Path(__file__).resolve().parent.parent
FIELD_MAPPING_PATH = _REPO_ROOT / "config" / "field_mapping.yaml"
DETECTIONS_PATH = _REPO_ROOT / "config" / "detections.yaml"


# ---------------------------------------------------------------- helpers
def format_timestamp(ts: datetime) -> str:
    """UTC ISO 8601 with millisecond precision, e.g. 2025-01-15T10:22:31.482Z."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def truncate_user_agent(ua: Optional[str]) -> Optional[str]:
    if ua is None:
        return None
    return ua[:USER_AGENT_MAX]


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value == "":
        return True
    if isinstance(value, (list, tuple, set, dict)) and len(value) == 0:
        return True
    return False


def _non_negative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    """Set key only when the value is available (never empty strings)."""
    if _is_missing(value):
        return
    if isinstance(value, (list, tuple, set)):
        value = list(value)
    out[key] = value


def _ts(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return format_timestamp(value)
    return str(value) or None


# ---------------------------------------------------------------- ground truth
@dataclass(frozen=True)
class GroundTruth:
    label: Optional[str] = None       # baseline | attack
    scenario: Optional[str] = None    # baseline | bola | jwt | ssrf
    technique: Optional[str] = None
    run_id: Optional[str] = None
    role: Optional[str] = None        # attack_action | setup

    def apply(self, out: dict[str, Any]) -> None:
        _put(out, "lab.ground_truth.label", self.label)
        _put(out, "lab.ground_truth.scenario", self.scenario)
        _put(out, "lab.ground_truth.technique", self.technique)
        _put(out, "lab.ground_truth.run_id", self.run_id)
        _put(out, "lab.ground_truth.role", self.role)


def _common(out: dict[str, Any], dataset: str, event_id: Optional[str], trace_id: str,
            start: datetime, duration_ns: int, source_ip: str) -> None:
    ts = format_timestamp(start)
    duration_ns = _non_negative_int(duration_ns)
    out["@timestamp"] = ts
    out["event.id"] = event_id or uuid.uuid4().hex
    out["event.dataset"] = dataset
    out["event.kind"] = "event"
    out["event.start"] = ts
    out["event.duration"] = duration_ns
    out["appsec.latency_ms"] = duration_ns // 1_000_000
    out["trace.id"] = trace_id
    out["source.ip"] = source_ip


# ---------------------------------------------------------------- builders
@dataclass
class TelemetryEvent:
    """api event (``appsec.api``)."""
    trace_id: str
    source_ip: str
    start: datetime
    duration_ns: int
    action: str                      # api_request | auth_login | jwt_validation_failed
    outcome: str                     # success | failure
    method: str
    status_code: int
    path: str
    endpoint_template: str
    category: Sequence[str] = ("web",)
    egress_count: int = 0
    event_id: Optional[str] = None
    user_agent: Optional[str] = None
    user_id: Optional[str] = None
    user_roles: Sequence[str] = ()
    tenant_id: Optional[str] = None
    resource_id: Optional[str] = None
    jwt_jti: Optional[str] = None
    jwt_alg: Optional[str] = None
    jwt_exp: Optional[datetime] = None
    jwt_expired: Optional[bool] = None
    jwt_verified: Optional[bool] = None
    resource_tenant_id: Optional[str] = None
    cross_tenant: Optional[bool] = None
    ground_truth: GroundTruth = field(default_factory=GroundTruth)

    def to_attributes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _common(out, DATASET_API, self.event_id, self.trace_id, self.start,
                self.duration_ns, self.source_ip)
        _put(out, "user_agent.original", truncate_user_agent(self.user_agent))
        _put(out, "event.category", self.category)
        out["event.action"] = self.action
        out["event.outcome"] = self.outcome
        _put(out, "user.id", self.user_id)
        _put(out, "user.roles", self.user_roles)
        _put(out, "organization.id", self.tenant_id)
        out["http.request.method"] = self.method
        out["http.response.status_code"] = int(self.status_code)
        out["url.path"] = self.path
        out["appsec.endpoint_template"] = self.endpoint_template
        _put(out, "appsec.resource_id", None if self.resource_id is None else str(self.resource_id))
        _put(out, "appsec.jwt.jti", self.jwt_jti)
        _put(out, "appsec.jwt.alg", self.jwt_alg)
        _put(out, "appsec.jwt.exp", _ts(self.jwt_exp))
        _put(out, "appsec.jwt.expired", self.jwt_expired)
        _put(out, "appsec.jwt.verified", self.jwt_verified)
        _put(out, "appsec.resource.tenant_id", self.resource_tenant_id)
        _put(out, "appsec.authz.cross_tenant", self.cross_tenant)
        out["appsec.egress.count"] = _non_negative_int(self.egress_count)
        self.ground_truth.apply(out)
        return out


@dataclass
class EgressEvent:
    """egress event (``appsec.egress``)."""
    trace_id: str
    source_ip: str
    start: datetime
    duration_ns: int
    destination_address: str
    url_full: str
    outcome: str                     # success | failure
    event_id: Optional[str] = None
    destination_domain: Optional[str] = None
    destination_port: Optional[int] = None
    destination_ip: Optional[str] = None
    status_code: Optional[int] = None
    error_type: Optional[str] = None  # dns_failure|connection_refused|timeout|invalid_url|other
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    endpoint_template: Optional[str] = None
    ground_truth: GroundTruth = field(default_factory=GroundTruth)

    def to_attributes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _common(out, DATASET_EGRESS, self.event_id, self.trace_id, self.start,
                self.duration_ns, self.source_ip)
        out["event.category"] = ["network"]
        out["event.outcome"] = self.outcome
        out["destination.address"] = self.destination_address
        _put(out, "destination.domain", self.destination_domain)
        _put(out, "destination.port", self.destination_port)
        _put(out, "destination.ip", self.destination_ip)
        out["url.full"] = self.url_full
        _put(out, "http.response.status_code", self.status_code)
        _put(out, "error.type", self.error_type)
        _put(out, "user.id", self.user_id)
        _put(out, "organization.id", self.tenant_id)
        _put(out, "appsec.endpoint_template", self.endpoint_template)
        self.ground_truth.apply(out)
        return out


# ---------------------------------------------------------------- models
@dataclass(frozen=True)
class AuthResult:
    present: bool = False
    alg: Optional[str] = None
    verified: bool = False
    claims: Mapping[str, Any] = field(default_factory=dict)
    jti: Optional[str] = None
    exp: Optional[datetime] = None
    expired: Optional[bool] = None
    accepted: bool = False


@dataclass(frozen=True)
class LabelledEvent:
    event_id: str
    label: Optional[str] = None
    scenario: Optional[str] = None
    role: Optional[str] = None
    trace_id: Optional[str] = None
    run_id: Optional[str] = None
    technique: Optional[str] = None

    @classmethod
    def from_attributes(cls, attrs: Mapping[str, Any]) -> "LabelledEvent":
        return cls(
            event_id=str(attrs.get("event.id", "")),
            label=attrs.get("lab.ground_truth.label"),
            scenario=attrs.get("lab.ground_truth.scenario"),
            role=attrs.get("lab.ground_truth.role"),
            trace_id=attrs.get("trace.id"),
            run_id=attrs.get("lab.ground_truth.run_id"),
            technique=attrs.get("lab.ground_truth.technique"),
        )


@dataclass(frozen=True)
class BolaConfig:
    window_minutes: int = 10
    lookback_minutes: int = 20
    distinct_ids_threshold: int = 25
    error_ratio_threshold: float = 0.6
    retry_suppression_max_ids: int = 3
    excluded_roles: tuple[str, ...] = ("batch_worker",)


@dataclass(frozen=True)
class JwtConfig:
    hijack_window_minutes: int = 5
    min_distinct_client_pairs: int = 2


@dataclass(frozen=True)
class SsrfConfig:
    internal_cidrs: tuple[str, ...] = ()
    internal_hostnames: tuple[str, ...] = ()
    allowed_destination_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectionConfig:
    bola: BolaConfig
    jwt: JwtConfig
    ssrf: SsrfConfig

    @classmethod
    def load(cls, path: Path | str = DETECTIONS_PATH) -> "DetectionConfig":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        b, j, s = raw.get("bola", {}), raw.get("jwt", {}), raw.get("ssrf", {})
        return cls(
            bola=BolaConfig(
                window_minutes=int(b.get("window_minutes", 10)),
                lookback_minutes=int(b.get("lookback_minutes", 20)),
                distinct_ids_threshold=int(b.get("distinct_ids_threshold", 25)),
                error_ratio_threshold=float(b.get("error_ratio_threshold", 0.6)),
                retry_suppression_max_ids=int(b.get("retry_suppression_max_ids", 3)),
                excluded_roles=tuple(b.get("excluded_roles", ["batch_worker"])),
            ),
            jwt=JwtConfig(
                hijack_window_minutes=int(j.get("hijack_window_minutes", 5)),
                min_distinct_client_pairs=int(j.get("min_distinct_client_pairs", 2)),
            ),
            ssrf=SsrfConfig(
                internal_cidrs=tuple(s.get("internal_cidrs", [])),
                internal_hostnames=tuple(s.get("internal_hostnames", [])),
                allowed_destination_hosts=tuple(s.get("allowed_destination_hosts", [])),
            ),
        )


def load_field_mapping(path: Path | str = FIELD_MAPPING_PATH) -> dict[str, Any]:
    """Load ``config/field_mapping.yaml``."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
