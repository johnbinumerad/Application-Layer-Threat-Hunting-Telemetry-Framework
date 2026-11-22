"""Sigma rule linting against the field mapping (Req 10.2, 10.3, 10.6).

Pure logic: ``check_document`` validates one parsed rule document, ``check_text``
a (possibly multi-document) YAML string, ``check_directory`` a directory of
``*.yml``/``*.yaml`` files. Rejected documents are reported with file name and
reason and excluded from the valid set.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from labcommon.schema import load_field_mapping

ALLOWED_LEVELS = ("informational", "low", "medium", "high", "critical")
_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z][a-z0-9-]*)$")
_OWASP_TAG = re.compile(r"^owasp\.api(10|[1-9])$")
_NON_FIELD_DETECTION_KEYS = {"condition", "timeframe"}


@dataclass
class Rejection:
    file: str
    reason: str

    def __str__(self) -> str:
        return f"{self.file}: {self.reason}"


@dataclass
class CheckResult:
    valid: list[str] = field(default_factory=list)  # "<file>#<n>" or file names of accepted docs
    rejected: list[Rejection] = field(default_factory=list)
    valid_files: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.rejected


def known_fields(mapping: Optional[dict[str, Any]] = None) -> set[str]:
    mapping = mapping if mapping is not None else load_field_mapping()
    return set(mapping.get("fields", {}).keys())


def is_valid_tag(tag: Any) -> bool:
    return isinstance(tag, str) and bool(_ATTACK_TAG.match(tag) or _OWASP_TAG.match(tag))


def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _collect_fields(node: Any, out: set[str]) -> None:
    """Collect field names (modifiers stripped) from a detection selection."""
    if isinstance(node, dict):
        for key, value in node.items():
            out.add(str(key).split("|", 1)[0])
            # values are literals; do not recurse into them
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                _collect_fields(item, out)


def referenced_fields(doc: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    detection = doc.get("detection")
    if isinstance(detection, dict):
        for key, sel in detection.items():
            if key in _NON_FIELD_DETECTION_KEYS:
                continue
            _collect_fields(sel, out)
    corr = doc.get("correlation")
    if isinstance(corr, dict):
        gb = corr.get("group-by")
        if isinstance(gb, list):
            out.update(g for g in gb if isinstance(g, str))
        cond = corr.get("condition")
        if isinstance(cond, dict) and isinstance(cond.get("field"), str):
            out.add(cond["field"])
    return out


def check_document(doc: Any, fields: set[str]) -> list[str]:
    """Return a list of reasons the document is invalid (empty when valid)."""
    if not isinstance(doc, dict):
        return ["document is not a YAML mapping"]
    errors: list[str] = []
    for key in ("title", "status", "description"):
        if not _nonempty_str(doc.get(key)):
            errors.append(f"missing or empty '{key}'")
    rid = doc.get("id")
    try:
        if not isinstance(rid, str):
            raise ValueError
        uuid.UUID(rid)
    except ValueError:
        errors.append("missing or invalid UUID 'id'")
    if not isinstance(doc.get("logsource"), dict) or not doc.get("logsource"):
        errors.append("missing or empty 'logsource'")

    detection = doc.get("detection")
    corr = doc.get("correlation")
    if isinstance(detection, dict):
        if not detection.get("condition"):
            errors.append("'detection' has no 'condition'")
    elif isinstance(corr, dict):
        # Correlation rule (value_count / temporal ...): no detection block.
        if not _nonempty_str(corr.get("type")):
            errors.append("'correlation' has no 'type'")
        if not isinstance(corr.get("rules"), list) or not corr.get("rules"):
            errors.append("'correlation' has no 'rules'")
        if not corr.get("timespan"):
            errors.append("'correlation' has no 'timespan'")
    else:
        errors.append("missing 'detection' with a 'condition'")

    fp = doc.get("falsepositives")
    if not isinstance(fp, list) or not fp:
        errors.append("missing or empty 'falsepositives'")
    if doc.get("level") not in ALLOWED_LEVELS:
        errors.append(f"'level' must be one of {', '.join(ALLOWED_LEVELS)}")
    tags = doc.get("tags")
    if not isinstance(tags, list) or not any(is_valid_tag(t) for t in tags):
        errors.append("needs at least one ATT&CK (attack.*) or OWASP (owasp.apiN) tag")

    unknown = sorted(f for f in referenced_fields(doc) if f not in fields)
    if unknown:
        errors.append("unknown field(s) not in field mapping: " + ", ".join(unknown))
    return errors


def check_text(text: str, name: str, fields: set[str]) -> tuple[list[dict], list[Rejection]]:
    """Check every YAML document in ``text``; returns (valid docs, rejections)."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return [], [Rejection(name, f"invalid YAML: {str(exc).splitlines()[0]}")]
    if not docs:
        return [], [Rejection(name, "file contains no Sigma rule")]
    valid: list[dict] = []
    rejected: list[Rejection] = []
    for i, doc in enumerate(docs, 1):
        label = name if len(docs) == 1 else f"{name} (document {i})"
        errs = check_document(doc, fields)
        if errs:
            rejected.append(Rejection(label, "; ".join(errs)))
        else:
            valid.append(doc)
    return valid, rejected


def check_directory(
    directory: Path | str, mapping: Optional[dict[str, Any]] = None
) -> CheckResult:
    """Lint all Sigma files; a file is valid only if all its documents are."""
    fields = known_fields(mapping)
    result = CheckResult()
    base = Path(directory)
    paths = sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml")))
    for p in paths:
        valid, rejected = check_text(p.read_text(encoding="utf-8"), p.name, fields)
        if rejected:
            result.rejected.extend(rejected)
        else:
            result.valid_files.append(p.name)
            result.valid.extend(f"{p.name}#{i}" for i in range(1, len(valid) + 1))
    return result


def is_correlation(doc: dict[str, Any]) -> bool:
    return isinstance(doc, dict) and "correlation" in doc and "detection" not in doc


def iter_rule_docs(directory: Path | str, names: Iterable[str]) -> Iterable[tuple[str, dict]]:
    for n in names:
        for doc in yaml.safe_load_all((Path(directory) / n).read_text(encoding="utf-8")):
            if doc:
                yield n, doc
