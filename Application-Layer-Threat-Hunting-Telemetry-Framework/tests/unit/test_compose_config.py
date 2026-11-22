"""Static tests for docker-compose.yml (Requirements 1.1, 1.4, 9.4, 9.5)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"

LONG_RUNNING = {"gateway", "target-api", "otel-collector", "opensearch", "dashboards", "jupyter"}
EDGE_SERVICES = {"gateway", "opensearch", "dashboards", "jupyter"}
CLOUD_PATTERN = re.compile(
    r"(AWS_|AZURE_|GCP_|GOOGLE_|OPENAI|ANTHROPIC|API_KEY|ACCESS_KEY|SECRET_KEY)", re.I
)


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text())


def _networks(svc: dict) -> set[str]:
    nets = svc.get("networks", [])
    return set(nets) if isinstance(nets, (list, dict)) else set()


def test_expected_services(compose):
    assert set(compose["services"]) == LONG_RUNNING | {"lab-setup"}


def test_lab_setup_is_one_shot(compose):
    assert compose["services"]["lab-setup"]["restart"] == "no"


def test_lab_internal_is_internal(compose):
    nets = compose["networks"]
    assert nets["lab_internal"]["internal"] is True
    assert nets["lab_internal"]["ipam"]["config"][0]["subnet"] == "172.28.0.0/16"
    assert not nets["lab_edge"].get("internal", False)


def test_every_service_on_lab_internal(compose):
    for name, svc in compose["services"].items():
        assert "lab_internal" in _networks(svc), name


def test_edge_membership(compose):
    on_edge = {n for n, s in compose["services"].items() if "lab_edge" in _networks(s)}
    assert on_edge == EDGE_SERVICES
    assert "lab_edge" not in _networks(compose["services"]["target-api"])
    assert "lab_edge" not in _networks(compose["services"]["otel-collector"])


def test_published_ports_loopback_only(compose):
    published = []
    for name, svc in compose["services"].items():
        for port in svc.get("ports", []):
            assert isinstance(port, str), f"{name}: use short string syntax"
            assert port.startswith("127.0.0.1:"), f"{name}: {port}"
            published.append(name)
    # Only edge services publish; target-api/collector never do.
    assert set(published) <= EDGE_SERVICES
    assert "target-api" not in published


def test_published_services_are_on_edge(compose):
    for name, svc in compose["services"].items():
        if svc.get("ports"):
            assert "lab_edge" in _networks(svc), name


def test_long_running_services_have_healthchecks(compose):
    for name in LONG_RUNNING:
        hc = compose["services"][name].get("healthcheck")
        assert hc and hc.get("test"), name
        assert hc.get("interval") == "5s", name
        assert hc.get("retries") == 3, name
        assert "start_period" in hc, name


def test_depends_on_healthy(compose):
    svcs = compose["services"]
    assert svcs["dashboards"]["depends_on"]["opensearch"]["condition"] == "service_healthy"
    deps = svcs["lab-setup"]["depends_on"]
    assert {deps["opensearch"]["condition"], deps["dashboards"]["condition"]} == {"service_healthy"}


def test_no_cloud_or_api_key_requirements(compose):
    for name, svc in compose["services"].items():
        env = svc.get("environment", {})
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env)
        for key, value in env.items():
            assert not CLOUD_PATTERN.search(key), f"{name}: {key}"
            # No required-variable interpolation (${VAR:?...} / ${VAR?...}).
            assert not re.search(r"\$\{[A-Za-z_]+:?\?", str(value)), f"{name}: {key}"
        assert "env_file" not in svc, name


def test_no_required_variable_interpolation_anywhere():
    assert not re.search(r"\$\{[A-Za-z_]+:?\?", COMPOSE.read_text())


def test_images_are_pinned(compose):
    for name, svc in compose["services"].items():
        if "image" in svc:
            assert ":" in svc["image"] and not svc["image"].endswith(":latest"), name
