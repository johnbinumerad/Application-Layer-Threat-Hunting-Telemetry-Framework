"""Validation orchestrator (Req 13.1, 13.2).

Runs baseline -> BOLA -> JWT -> SSRF strictly in order, one at a time, with a
per-component cap of 30 minutes. On a non-zero exit or a timeout it stops,
reports the failing component and runs nothing later. It never deletes
telemetry (it has no access to the SIEM at all).

Collaborators are injected: a ``Runner`` executes one component and returns a
``RunOutcome``. ``subprocess_runner`` is the default real implementation.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

COMPONENT_ORDER: tuple[str, ...] = ("baseline", "bola", "jwt", "ssrf")
COMPONENT_TIMEOUT_S: float = 30 * 60

COMPONENT_MODULES: dict[str, str] = {
    "baseline": "simulators.traffic_baseline",
    "bola": "simulators.hunt_01_bola_enum",
    "jwt": "simulators.hunt_02_jwt_abuse",
    "ssrf": "simulators.hunt_03_ssrf_egress",
}


@dataclass(frozen=True)
class RunOutcome:
    """Result of running one component. ``exit_code`` is None on timeout."""

    exit_code: int | None
    timed_out: bool = False


# runner(component, timeout_s) -> RunOutcome
Runner = Callable[[str, float], RunOutcome]


@dataclass
class ComponentResult:
    component: str
    exit_code: int | None
    timed_out: bool
    duration_s: float

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


@dataclass
class OrchestrationResult:
    results: list[ComponentResult] = field(default_factory=list)
    failed_component: str | None = None
    failure_reason: str | None = None
    # Telemetry is always retained by the orchestrator (Req 13.2).
    telemetry_retained: bool = True

    @property
    def success(self) -> bool:
        return self.failed_component is None

    @property
    def completed(self) -> list[str]:
        return [r.component for r in self.results if r.ok]


def run_validation(
    runner: Runner,
    components: Sequence[str] = COMPONENT_ORDER,
    timeout_s: float = COMPONENT_TIMEOUT_S,
    clock: Callable[[], float] = time.monotonic,
) -> OrchestrationResult:
    """Run components sequentially; stop at the first failure or timeout."""
    out = OrchestrationResult()
    for component in components:
        start = clock()
        try:
            outcome = runner(component, timeout_s)
        except Exception as exc:  # runner crash counts as a component failure
            out.results.append(
                ComponentResult(component, None, False, clock() - start)
            )
            out.failed_component = component
            out.failure_reason = f"runner error: {exc}"
            return out
        res = ComponentResult(
            component, outcome.exit_code, outcome.timed_out, clock() - start
        )
        out.results.append(res)
        if not res.ok:
            out.failed_component = component
            out.failure_reason = (
                f"timed out after {timeout_s:g}s"
                if outcome.timed_out
                else f"exited with status {outcome.exit_code}"
            )
            return out
    return out


def subprocess_runner(
    extra_args: dict[str, list[str]] | None = None,
    python: str = sys.executable,
) -> Runner:
    """Default runner: ``python -m <simulator module> [args]`` per component."""
    extra_args = extra_args or {}

    def run(component: str, timeout_s: float) -> RunOutcome:
        cmd = [python, "-m", COMPONENT_MODULES[component], *extra_args.get(component, [])]
        try:
            proc = subprocess.run(cmd, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return RunOutcome(None, timed_out=True)
        return RunOutcome(proc.returncode)

    return run


def format_failure(result: OrchestrationResult) -> str:
    """Human-readable report of which component failed."""
    if result.success:
        return "validation run completed: " + ", ".join(result.completed)
    return (
        f"validation run stopped: component '{result.failed_component}' "
        f"{result.failure_reason}; telemetry generated so far was retained"
    )
