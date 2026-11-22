"""Target safety validation for Attack_Simulators (Req 9.1-9.3)."""
from __future__ import annotations

import socket
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

EXIT_OUTSIDE_LAB = 2
RESOLVE_TIMEOUT_S = 3.0
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "lab.toml"

Resolver = Callable[[str, int], Iterable[str]]


@dataclass(frozen=True)
class GatewayConfig:
    bind_host: str = "127.0.0.1"
    port: int = 8080
    scheme: str = "http"


class TargetOutsideLab(Exception):
    exit_code = EXIT_OUTSIDE_LAB


def load_gateway(path: Path | str = DEFAULT_CONFIG) -> GatewayConfig:
    with open(path, "rb") as f:
        g = tomllib.load(f)["gateway"]
    return GatewayConfig(g["bind_host"], int(g["port"]), g.get("scheme", "http"))


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [i[4][0] for i in infos]


def _resolve_with_timeout(resolver: Resolver, host: str, port: int, timeout: float) -> list[str]:
    ex = ThreadPoolExecutor(max_workers=1)
    try:
        return list(ex.submit(lambda: list(resolver(host, port))).result(timeout=timeout))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def _reject(target: str) -> TargetOutsideLab:
    return TargetOutsideLab(f"error: target {target} is outside the Lab")


def check_target(
    url: str,
    gateway: GatewayConfig | None = None,
    resolver: Resolver = system_resolver,
    timeout: float = RESOLVE_TIMEOUT_S,
) -> None:
    """Raise TargetOutsideLab unless url is http, on the gateway port, and every
    resolved address equals the configured loopback gateway bind."""
    gw = gateway or load_gateway()
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
        scheme = parts.scheme
    except ValueError:
        raise _reject(url) from None
    if scheme != "http" or gw.scheme != "http" or not host:
        raise _reject(url)
    if (port if port is not None else 80) != gw.port:
        raise _reject(url)
    try:
        addrs = _resolve_with_timeout(resolver, host, gw.port, timeout)
    except (FutureTimeout, OSError, Exception):  # noqa: BLE001 - any failure means reject
        raise _reject(url) from None
    if not addrs or any(a != gw.bind_host for a in addrs):
        raise _reject(url)


def validate_target(
    url: str,
    gateway: GatewayConfig | None = None,
    resolver: Resolver = system_resolver,
    timeout: float = RESOLVE_TIMEOUT_S,
    stderr=None,
) -> None:
    """Validate before any request. On failure: message to stderr, SystemExit(2)."""
    try:
        check_target(url, gateway, resolver, timeout)
    except TargetOutsideLab as e:
        print(str(e), file=stderr or sys.stderr)
        raise SystemExit(EXIT_OUTSIDE_LAB) from None
