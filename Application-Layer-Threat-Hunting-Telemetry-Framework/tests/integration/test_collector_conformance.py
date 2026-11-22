"""Static conformance tests for the OTel Collector configs and entrypoint (task 2.7).

Docker/otelcol are not required: configs are parsed as YAML and the entrypoint is run
with `sh` against a stub collector. Live-collector tests are skipped when no binary/Docker.

Validates: Requirements 4.1, 4.2, 4.3, 4.5, 4.6, 4.7
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

OTEL_DIR = Path(__file__).resolve().parents[2] / "infra" / "otel"
MAIN_CFG = OTEL_DIR / "otel-config.yaml"
NOSALT_CFG = OTEL_DIR / "otel-config.nosalt.yaml"
ENTRYPOINT = OTEL_DIR / "entrypoint.sh"


@pytest.fixture(scope="module")
def main_cfg() -> dict:
    return yaml.safe_load(MAIN_CFG.read_text())


@pytest.fixture(scope="module")
def nosalt_cfg() -> dict:
    return yaml.safe_load(NOSALT_CFG.read_text())


def _all_statements(cfg: dict, processor: str) -> list[str]:
    return [s for blk in cfg["processors"][processor]["log_statements"] for s in blk["statements"]]


# ---------------------------------------------------------------- main config


def test_main_pipeline_structure(main_cfg):
    pipes = main_cfg["service"]["pipelines"]
    ingest = pipes["logs/ingest"]
    assert ingest["receivers"] == ["otlp"]
    # enrich (hash) -> scrub (remove) -> seal (verify) ordering, memory limiter first.
    assert ingest["processors"] == [
        "memory_limiter",
        "transform/enrich",
        "transform/scrub",
        "transform/seal",
    ]
    assert ingest["exporters"] == ["routing"]
    assert pipes["logs/export"]["receivers"] == ["routing"]
    assert pipes["logs/export"]["exporters"] == ["opensearch"]


def test_only_export_pipeline_reaches_opensearch(main_cfg):
    for name, pipe in main_cfg["service"]["pipelines"].items():
        has_os = "opensearch" in pipe.get("exporters", [])
        assert has_os == (name == "logs/export"), name


def test_routing_fails_closed(main_cfg):
    routing = main_cfg["connectors"]["routing"]
    assert routing["default_pipelines"] == ["logs/scrub_failed"]
    assert len(routing["table"]) == 1
    entry = routing["table"][0]
    assert entry["pipelines"] == ["logs/export"]
    assert 'attributes["appsec.scrub.status"] == "ok"' in entry["condition"]


def test_scrub_failed_pipeline_reduces_and_never_exports_to_opensearch(main_cfg):
    failed = main_cfg["service"]["pipelines"]["logs/scrub_failed"]
    assert failed["receivers"] == ["routing"]
    assert failed["processors"] == ["transform/reduce"]
    assert "opensearch" not in failed["exporters"]
    stmts = _all_statements(main_cfg, "transform/reduce")
    assert any("keep_keys" in s and "event.id" in s and "trace.id" in s for s in stmts)
    # Only identifiers survive: no other key may be whitelisted.
    keep = [s for s in stmts if "keep_keys" in s][0]
    assert keep.count('"') == 4  # exactly two whitelisted keys


def test_scrub_deletes_sensitive_fields_and_redacts(main_cfg):
    stmts = _all_statements(main_cfg, "transform/scrub")
    joined = "\n".join(stmts)
    assert 'delete_key(attributes, "http.request.headers.authorization")' in joined
    assert 'delete_key(attributes, "appsec.credentials.password")' in joined
    assert "eyJ" in joined and "bearer" in joined.lower()
    assert 'set(body, "")' in joined


def test_enrich_hashes_before_scrub_and_keeps_plain_jti(main_cfg):
    stmts = _all_statements(main_cfg, "transform/enrich")
    joined = "\n".join(stmts)
    assert "appsec.jwt.token_hash" in joined and "appsec.jwt.jti_hash" in joined
    assert "${env:SCRUB_SALT}" in joined
    assert not any('delete_key(attributes, "appsec.jwt.jti")' in s for s in stmts)
    order = main_cfg["service"]["pipelines"]["logs/ingest"]["processors"]
    assert order.index("transform/enrich") < order.index("transform/scrub")


def test_seal_is_after_scrub_and_conditional(main_cfg):
    order = main_cfg["service"]["pipelines"]["logs/ingest"]["processors"]
    assert order.index("transform/scrub") < order.index("transform/seal")
    stmts = _all_statements(main_cfg, "transform/seal")
    assert len(stmts) == 1
    s = stmts[0]
    assert 'set(attributes["appsec.scrub.status"], "ok")' in s and " where " in s
    # Nothing else sets status=ok anywhere in the config.
    assert MAIN_CFG.read_text().count('"appsec.scrub.status"], "ok"') == 1


def test_no_processor_other_than_seal_sets_ok(main_cfg):
    for name in ("transform/enrich", "transform/scrub", "transform/reduce"):
        assert "appsec.scrub.status" not in "\n".join(_all_statements(main_cfg, name))


def test_defined_components_are_wired(main_cfg):
    used = set()
    for pipe in main_cfg["service"]["pipelines"].values():
        for k in ("receivers", "processors", "exporters"):
            used.update(pipe.get(k, []))
    for section in ("receivers", "processors", "exporters", "connectors"):
        for comp in main_cfg.get(section, {}):
            assert comp in used, f"{section}/{comp} defined but unused"
    for comp in used:
        assert any(comp in main_cfg.get(s, {}) for s in ("receivers", "processors", "exporters", "connectors")), comp


# ---------------------------------------------------------------- nosalt config


def test_nosalt_has_no_opensearch_exporter(nosalt_cfg):
    assert "opensearch" not in nosalt_cfg.get("exporters", {})
    for pipe in nosalt_cfg["service"]["pipelines"].values():
        assert "opensearch" not in pipe["exporters"]
        assert not any(e.startswith(("otlp", "opensearch", "file")) for e in pipe["exporters"])


def test_nosalt_drops_everything_and_has_health_check(nosalt_cfg):
    pipe = nosalt_cfg["service"]["pipelines"]["logs"]
    assert pipe["receivers"] == ["otlp"]
    assert pipe["processors"] == ["filter/drop_all"]
    assert nosalt_cfg["processors"]["filter/drop_all"]["logs"]["log_record"] == ["true"]
    assert "health_check" in nosalt_cfg["service"]["extensions"]
    assert nosalt_cfg["extensions"]["health_check"]["endpoint"].endswith(":13133")


def test_nosalt_does_not_reference_salt(nosalt_cfg):
    assert "SCRUB_SALT" not in NOSALT_CFG.read_text().replace("SCRUB_SALT is not configured", "")


# ---------------------------------------------------------------- entrypoint


def _run_entrypoint(tmp_path: Path, env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    """Run a copy of entrypoint.sh with the collector path replaced by a stub that echoes its argv."""
    stub = tmp_path / "otelcol-contrib"
    stub.write_text('#!/bin/sh\necho "STUB_ARGS: $*"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    cfg_dir = tmp_path / "etc"
    cfg_dir.mkdir()
    script = ENTRYPOINT.read_text().replace("/otelcol-contrib", str(stub)).replace("/etc/otelcol", str(cfg_dir))
    ep = tmp_path / "entrypoint.sh"
    ep.write_text(script)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(env_extra)
    return subprocess.run(["sh", str(ep)], env=env, capture_output=True, text=True, timeout=20)


def test_entrypoint_uses_nosalt_when_salt_unset(tmp_path):
    r = _run_entrypoint(tmp_path, {})
    assert r.returncode == 0
    assert "otel-config.nosalt.yaml" in r.stdout
    assert "FATAL" in r.stderr and "SCRUB_SALT" in r.stderr


def test_entrypoint_uses_nosalt_when_salt_empty(tmp_path):
    r = _run_entrypoint(tmp_path, {"SCRUB_SALT": ""})
    assert "otel-config.nosalt.yaml" in r.stdout
    assert "FATAL" in r.stderr


def test_entrypoint_uses_main_config_when_salt_set(tmp_path):
    r = _run_entrypoint(tmp_path, {"SCRUB_SALT": "pepper"})
    assert r.returncode == 0
    assert "otel-config.yaml" in r.stdout and "nosalt" not in r.stdout
    assert r.stderr == ""
    assert "pepper" not in r.stdout + r.stderr


@pytest.mark.parametrize("config", ["otel-config.yaml", "otel-config.nosalt.yaml"])
def test_entrypoint_targets_existing_configs(config):
    assert config in ENTRYPOINT.read_text()
    assert (OTEL_DIR / config).is_file()


# ---------------------------------------------------------------- live (skipped)

_HAVE_LIVE = bool(shutil.which("otelcol-contrib") or shutil.which("docker"))


@pytest.mark.skipif(
    not _HAVE_LIVE,
    reason="No otelcol-contrib binary or Docker found; live Collector tests (Properties 11-14 via "
    "OTLP + file exporter, missing-salt health check) cannot run in this environment",
)
def test_live_collector_properties_11_to_14():  # pragma: no cover
    pytest.skip("Live collector harness not implemented; requires a file-exporter config variant")
