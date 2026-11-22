"""Property 32: Sigma lint.

sigma-check accepts a rule document iff it has all required fields, a UUID id,
an allowed level, at least one ATT&CK/OWASP tag, and only mapped field names.
Rejected files are reported with file name and reason and excluded from the valid set.

**Validates: Requirements 10.2, 10.3, 10.6**
"""
import copy
import re
import uuid

import yaml
from hypothesis import given, strategies as st

from labcommon.sigma_check import (
    ALLOWED_LEVELS,
    check_directory,
    check_document,
    check_text,
)

FIELDS = {"event.dataset", "http.response.status_code", "user.id", "source.ip", "appsec.jwt.alg"}
UNKNOWN = ["not.a.field", "lab.ground_truth.label", "foo"]
TAG_RE = re.compile(r"^(attack\.(t\d{4}(\.\d{3})?|[a-z][a-z0-9-]*)|owasp\.api(10|[1-9]))$")

REQUIRED_KEYS = ["title", "id", "status", "description", "logsource", "detection",
                 "falsepositives", "level", "tags"]

words = st.text(alphabet="abcdefghij klmnop", min_size=1, max_size=20).filter(lambda s: s.strip())
good_tags = st.sampled_from(["attack.t1087", "attack.t1550.001", "owasp.api1", "owasp.api10",
                             "attack.defense-evasion"])
bad_tags = st.sampled_from(["foo", "owasp.api0", "owasp.api11", "attack.T1087", "attack.t12", "", "mitre.t1087"])
mod = st.sampled_from(["", "|contains", "|gte", "|exists"])


@st.composite
def valid_docs(draw):
    flds = draw(st.lists(st.sampled_from(sorted(FIELDS)), min_size=1, max_size=3, unique=True))
    sel = {f + draw(mod): draw(st.sampled_from(["x", 1, True])) for f in flds}
    return {
        "title": draw(words),
        "id": str(uuid.UUID(int=draw(st.integers(0, 2**128 - 1)))),
        "status": draw(st.sampled_from(["stable", "test", "experimental"])),
        "description": draw(words),
        "logsource": {"category": "application", "product": "appsec-lab"},
        "detection": {"selection": sel, "condition": "selection"},
        "falsepositives": draw(st.lists(words, min_size=1, max_size=2)),
        "level": draw(st.sampled_from(ALLOWED_LEVELS)),
        "tags": draw(st.lists(good_tags, min_size=1, max_size=3)) + draw(st.lists(bad_tags, max_size=2)),
    }


def oracle(doc):
    """Independent statement of the acceptance rule (detection-style rules)."""
    try:
        uuid.UUID(doc["id"])
        uid = True
    except (KeyError, ValueError, TypeError, AttributeError):
        uid = False
    ne = lambda k: isinstance(doc.get(k), str) and doc[k].strip() != ""
    det = doc.get("detection")
    flds = {k.split("|")[0] for k, v in (det or {}).get("selection", {}).items()} if isinstance(det, dict) else set()
    return (
        ne("title") and ne("status") and ne("description") and uid
        and bool(doc.get("logsource"))
        and isinstance(det, dict) and bool(det.get("condition"))
        and bool(doc.get("falsepositives"))
        and doc.get("level") in ALLOWED_LEVELS
        and any(isinstance(t, str) and TAG_RE.match(t) for t in doc.get("tags", []))
        and flds <= FIELDS
    )


@st.composite
def mutated_docs(draw):
    doc = draw(valid_docs())
    kind = draw(st.sampled_from([
        "none", "drop", "bad_uuid", "bad_level", "bad_tags", "unknown_field",
        "no_condition", "empty_fp",
    ]))
    if kind == "drop":
        del doc[draw(st.sampled_from(REQUIRED_KEYS))]
    elif kind == "bad_uuid":
        doc["id"] = draw(st.sampled_from(["", "not-a-uuid", "1234", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"]))
    elif kind == "bad_level":
        doc["level"] = draw(st.sampled_from(["", "severe", "HIGH", "urgent"]))
    elif kind == "bad_tags":
        doc["tags"] = draw(st.lists(bad_tags, max_size=3))
    elif kind == "unknown_field":
        doc["detection"]["selection"][draw(st.sampled_from(UNKNOWN))] = "x"
    elif kind == "no_condition":
        del doc["detection"]["condition"]
    elif kind == "empty_fp":
        doc["falsepositives"] = []
    return doc


@given(mutated_docs())
def test_accepts_iff_all_requirements_hold(doc):
    assert (check_document(copy.deepcopy(doc), FIELDS) == []) == oracle(doc)


@given(valid_docs())
def test_valid_doc_accepted_via_text(doc):
    valid, rejected = check_text(yaml.safe_dump(doc), "r.yml", FIELDS)
    assert rejected == [] and len(valid) == 1


@given(mutated_docs())
def test_rejections_report_file_and_reason(doc):
    valid, rejected = check_text(yaml.safe_dump(doc), "rule.yml", FIELDS)
    if oracle(doc):
        assert valid and not rejected
    else:
        assert not valid and len(rejected) == 1
        assert rejected[0].file == "rule.yml" and rejected[0].reason
        assert str(rejected[0]).startswith("rule.yml: ")


@given(st.lists(mutated_docs(), min_size=1, max_size=4))
def test_directory_excludes_rejected_files(tmp_path_factory, docs):
    d = tmp_path_factory.mktemp("sigma")
    for i, doc in enumerate(docs):
        (d / f"rule{i}.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    res = check_directory(d, {"fields": {f: {} for f in FIELDS}})
    expected_valid = {f"rule{i}.yml" for i, doc in enumerate(docs) if oracle(doc)}
    expected_bad = {f"rule{i}.yml" for i, doc in enumerate(docs) if not oracle(doc)}
    assert set(res.valid_files) == expected_valid
    assert {r.file for r in res.rejected} == expected_bad
    assert res.ok == (not expected_bad)
