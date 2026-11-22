"""Reference model of the Collector scrub / seal / route logic (Req 4).

Pure Python oracle for collector conformance tests. Records are flat dicts of
attribute name -> value (the OTLP log record attributes), plus an optional
``body``. Mirrors the pipeline stages: enrich (salted hashes), scrub (delete
password and raw Authorization, regex redaction), seal (set
``appsec.scrub.status="ok"`` only after verification), route (sealed -> export,
unsealed -> reduce/count/log). Fail closed: any error leaves a record unsealed.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

AUTH_KEY = "http.request.headers.authorization"
PASSWORD_KEY = "appsec.credentials.password"
JTI_KEY = "appsec.jwt.jti"
TOKEN_HASH_KEY = "appsec.jwt.token_hash"
JTI_HASH_KEY = "appsec.jwt.jti_hash"
STATUS_KEY = "appsec.scrub.status"
EVENT_ID_KEY = "event.id"
TRACE_ID_KEY = "trace.id"
PLACEHOLDER = "[REDACTED]"
SENSITIVE_KEYS = (AUTH_KEY, PASSWORD_KEY)

BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

_SCALARS = (str, int, float, bool, type(None))


class ScrubError(Exception):
    """Raised when a record cannot be scrubbed (e.g. unsupported value type)."""


def salted_hash(salt: str, value: str) -> str:
    """Full salted SHA-256 hex digest: SHA256(salt + value)."""
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


def jti_hash(salt: str, jti: str) -> str:
    """Pseudonymous JTI pivot: first 16 hex chars of the salted hash."""
    return salted_hash(salt, jti)[:16]


def _redact(value: Any) -> Any:
    """Redact Bearer/JWT strings; recurse into lists/dicts; reject other types."""
    if isinstance(value, str):
        return JWT_RE.sub(PLACEHOLDER, BEARER_RE.sub(PLACEHOLDER, value))
    if isinstance(value, _SCALARS):
        return value
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _redact(v) for k, v in value.items()}
    raise ScrubError(f"unsupported attribute type: {type(value).__name__}")


def _contains_sensitive(value: Any) -> bool:
    if isinstance(value, str):
        return bool(BEARER_RE.search(value) or JWT_RE.search(value))
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive(v) for v in value)
    if isinstance(value, dict):
        return any(
            k in SENSITIVE_KEYS or _contains_sensitive(v) for k, v in value.items()
        )
    return False


def scrub_record(record: Mapping[str, Any], salt: str) -> Dict[str, Any]:
    """Enrich + scrub one record and seal it. Returns the output record.

    The returned record carries ``appsec.scrub.status="ok"`` only if
    verification passes; otherwise it is returned unsealed (no status key).
    Never mutates the input.
    """
    out: Dict[str, Any] = {}
    try:
        attrs = dict(record)
        # enrich: salted hashes (before sensitive keys are deleted)
        auth = attrs.get(AUTH_KEY)
        if isinstance(auth, str) and auth.startswith("Bearer "):
            attrs[TOKEN_HASH_KEY] = salted_hash(salt, auth[7:])
        jti = attrs.get(JTI_KEY)
        if jti is not None:
            if not isinstance(jti, str):
                raise ScrubError("jti must be a string")
            attrs[JTI_HASH_KEY] = jti_hash(salt, jti)
        # scrub: delete sensitive keys outright (no length leak), redact strays
        for key in SENSITIVE_KEYS:
            attrs.pop(key, None)
        attrs.pop(STATUS_KEY, None)  # status can only be set by the sealer
        if "body" in attrs:
            attrs["body"] = ""
        for key, value in attrs.items():
            if key == JTI_KEY:
                out[key] = value  # JTI is preserved in plain form (Req 4.6)
            else:
                out[key] = _redact(value)
        # seal: only after verification
        if not any(k in out for k in SENSITIVE_KEYS) and not any(
            _contains_sensitive(v) for k, v in out.items() if k != JTI_KEY
        ):
            out[STATUS_KEY] = "ok"
    except Exception:  # fail closed: any error leaves the record unsealed
        out.pop(STATUS_KEY, None)
    return out


def is_sealed(record: Mapping[str, Any]) -> bool:
    return record.get(STATUS_KEY) == "ok"


def reduce_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Keep only the record identifiers (event.id, trace.id); body cleared."""
    reduced: Dict[str, Any] = {}
    for key in (EVENT_ID_KEY, TRACE_ID_KEY):
        v = record.get(key)
        if isinstance(v, str) and not (BEARER_RE.search(v) or JWT_RE.search(v)):
            reduced[key] = v
    return reduced


@dataclass
class ScrubResult:
    exported: List[Dict[str, Any]] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)  # reduced records
    log: List[Tuple[int, Dict[str, Any]]] = field(default_factory=list)
    failure_count: int = 0


class ScrubberModel:
    """Stateful model: salted scrubbing, fail-closed routing, failure counter."""

    def __init__(self, salt: Optional[str]):
        self.salt = salt
        self.failure_count = 0
        self.log: List[Tuple[int, Dict[str, Any]]] = []

    @property
    def forwarding_enabled(self) -> bool:
        """Req 4.7: with a missing/empty salt nothing is forwarded."""
        return bool(self.salt)

    def process(self, records: List[Mapping[str, Any]]) -> ScrubResult:
        result = ScrubResult()
        if not self.forwarding_enabled:
            result.failure_count = self.failure_count
            return result
        for rec in records:
            scrubbed = scrub_record(rec, self.salt or "")
            if is_sealed(scrubbed):
                result.exported.append(scrubbed)
            else:
                reduced = reduce_record(rec if isinstance(rec, Mapping) else {})
                self.failure_count += 1
                entry = (self.failure_count, reduced)
                self.log.append(entry)
                result.failed.append(reduced)
                result.log.append(entry)
        result.failure_count = self.failure_count
        return result
