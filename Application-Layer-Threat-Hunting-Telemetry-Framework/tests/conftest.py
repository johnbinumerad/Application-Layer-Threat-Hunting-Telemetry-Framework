"""Shared pytest configuration: Hypothesis profile with >=100 examples and printed seeds."""
import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "lab",
    max_examples=int(os.environ.get("HYPOTHESIS_MAX_EXAMPLES", "100")),
    print_blob=True,  # print reproduction blob / seed on failure
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("lab")


def pytest_addoption(parser):  # pragma: no cover - plumbing
    pass


def pytest_report_header(config):
    return "hypothesis profile: lab (max_examples>=100, blobs/seeds printed)"
