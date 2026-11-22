"""Documentation consistency tests (task 12.4).

Validates: Requirements 1.7, 2.13, 10.1, 10.4, 11.1, 12.1, 13.8
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()
WEAKNESSES = (ROOT / "docs" / "weaknesses.md").read_text()
DETECTIONS_MD = (ROOT / "docs" / "detections.md").read_text()
FIELD_MD = (ROOT / "docs" / "field-mapping.md").read_text()
DETECTIONS = yaml.safe_load((ROOT / "config" / "detections.yaml").read_text())
FIELDS = yaml.safe_load((ROOT / "config" / "field_mapping.yaml").read_text())

# Backticked dotted tokens that are dataset names / namespaces, not fields.
NON_FIELD_TOKENS = {"appsec.api", "appsec.egress", "appsec.gateway", "appsec.*", "lab.*"}
ROOTS = {"appsec", "lab", "event", "http", "url", "user", "user_agent", "source",
         "destination", "organization", "trace", "error"}


def _doc_fields(text: str) -> set[str]:
    tokens = set(re.findall(r"`([@A-Za-z_][A-Za-z0-9_.@]*)`", text))
    return {
        t for t in tokens
        if "." in t and t.split(".")[0] in ROOTS and t not in NON_FIELD_TOKENS
        and not t.endswith(".")
    }


def _table_row(text: str, key: str) -> list[str]:
    for line in text.splitlines():
        if line.startswith("|") and f"`{key}`" in line.split("|")[1]:
            return [c.strip() for c in line.strip().strip("|").split("|")]
    raise AssertionError(f"row for {key} not found")


# ---- README host requirements (1.7, 10.4) ----
def test_readme_states_host_requirements():
    assert re.search(r"CPU cores\s*\|\s*\d+", README)
    assert re.search(r"Memory\s*\|\s*\d+\s*GB", README)
    assert re.search(r"Free disk\s*\|\s*\d+\s*GB", README)
    assert re.search(r"Docker Engine\s*\|\s*\d+(\.\d+)*", README)
    assert re.search(r"Docker Compose\s*\|\s*v?\d+(\.\d+)*", README)


def test_readme_states_ecs_not_ocsf_and_five_services():
    assert "ECS, not OCSF" in README
    assert "Five logical services" in README
    assert "loopback" in README.lower()


# ---- weaknesses (2.13) ----
def test_weaknesses_lists_four_with_endpoint_and_owasp():
    rows = [
        [c.strip() for c in line.strip().strip("|").split("|")]
        for line in WEAKNESSES.splitlines()
        if re.match(r"\|\s*\d+\s*\|", line)
    ]
    assert len(rows) == 4
    for _num, _name, endpoint, owasp in rows:
        assert re.search(r"`(GET|POST|PUT|DELETE) /api/v1/\S+`", endpoint)
        assert re.search(r"API\d+:2023", owasp)


# ---- thresholds (10.1) ----
def test_detections_md_thresholds_match_yaml():
    for key, section in (("bola", DETECTIONS["bola"]), ("jwt", DETECTIONS["jwt"])):
        for name, value in section.items():
            if isinstance(value, list):
                continue
            m = re.search(rf"`{key}\.{name}`\s*\|\s*([0-9.]+)\s*\|", DETECTIONS_MD)
            assert m, f"{key}.{name} missing from docs/detections.md"
            assert float(m.group(1)) == float(value), f"{key}.{name} differs"
    m = re.search(r"`bola\.excluded_roles`\s*\|\s*([^|]+)\|", DETECTIONS_MD)
    assert m
    for role in DETECTIONS["bola"]["excluded_roles"]:
        assert role in m.group(1)


def test_detections_md_ssrf_lists_match_yaml():
    for key in ("internal_cidrs", "internal_hostnames"):
        m = re.search(rf"`ssrf\.{key}`\s*\|\s*([^|]+)\|", DETECTIONS_MD)
        assert m
        documented = {s.strip() for s in m.group(1).split(",")}
        assert documented == set(DETECTIONS["ssrf"][key])
    assert DETECTIONS["ssrf"]["allowed_destination_hosts"] == []


# ---- monitor / sigma counts (11.1, 12.1) ----
def test_exactly_three_monitors_and_three_sigma_files():
    assert len(list((ROOT / "opensearch" / "monitors").glob("*.json"))) == 3
    assert len(list((ROOT / "detections" / "sigma").glob("*.yml"))) == 3
    for rel in re.findall(r"`((?:detections/sigma|opensearch/monitors)/[\w.]+)`", DETECTIONS_MD):
        assert (ROOT / rel).exists(), f"{rel} referenced in docs but missing"


# ---- field mapping (13.8) ----
def test_every_documented_field_exists_in_field_mapping_yaml():
    known = set(FIELDS["fields"]) | set(FIELDS["removed_before_indexing"])
    # The "supplied design name" table intentionally lists non-ECS legacy names.
    field_md = re.sub(r"## Supplied-design name to ECS name.*?(?=\n## )", "", FIELD_MD, flags=re.S)
    for name, text in (("field-mapping.md", field_md), ("detections.md", DETECTIONS_MD),
                       ("weaknesses.md", WEAKNESSES)):
        missing = _doc_fields(text) - known
        assert not missing, f"{name} documents fields not in field_mapping.yaml: {sorted(missing)}"


def test_field_mapping_md_has_every_yaml_field():
    documented = _doc_fields(FIELD_MD) | {"@timestamp"}
    assert set(FIELDS["fields"]) <= documented


def test_field_mapping_md_types_and_presence_match_yaml():
    section = FIELD_MD.split("## Telemetry_Event")[1].split("## Egress_Event")[0]
    for name, spec in FIELDS["fields"].items():
        if "appsec.api" not in spec["datasets"] or spec.get("stage") or name.startswith("lab."):
            continue
        row = _table_row(section, name)
        assert row[1] == spec["type"], f"{name} type"
        if spec["presence"] == "required":
            assert row[2] == "R", f"{name} presence"
        else:
            assert row[2] == "C", f"{name} presence"
