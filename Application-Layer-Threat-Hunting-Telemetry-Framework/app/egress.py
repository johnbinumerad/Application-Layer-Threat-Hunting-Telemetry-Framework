"""Instrumented outbound URL fetch for the webhook preview (intentionally SSRF-prone).

``safe_fetch`` is named for its structure, not its safety: it applies NO destination
filtering. Loopback, link-local, RFC 1918 and internal hostnames are fetched and
previewed. Exactly one Egress_Event (``appsec.egress``) is emitted per call, in a
``finally`` block, whatever the outcome.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, MutableMapping, Optional
from urllib.parse import urlsplit

import httpx

from app.telemetry import emit_event
from labcommon.schema import EgressEvent, GroundTruth

FETCH_TIMEOUT_S = 4.5
PREVIEW_CHARS = 4096

DNS_FAILURE = "dns_failure"
CONNECTION_REFUSED = "connection_refused"
TIMEOUT = "timeout"
INVALID_URL = "invalid_url"
OTHER = "other"

# Hosts spelled only with digits, hex digits, 'x' and dots are numeric IPv4 forms
# (decimal, octal, hex), not domain names.
_NUMERIC_HOST = re.compile(r"^(0[xX][0-9a-fA-F]+|[0-9]+)(\.(0[xX][0-9a-fA-F]+|[0-9]+))*$")

Resolver = Callable[[str, int], Awaitable[str]]


class EgressError(Exception):
    """Raised by ``safe_fetch`` on failure; ``error_type`` is the telemetry class."""

    def __init__(self, error_type: str, message: str = "") -> None:
        super().__init__(message or error_type)
        self.error_type = error_type


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    body: str  # first PREVIEW_CHARS characters


async def _default_resolver(host: str, port: int) -> str:
    """Resolve once with getaddrinfo (accepts decimal/octal/hex/IPv6-mapped forms)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise socket.gaierror("no address")
    return infos[0][4][0]


def _is_domain(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return not _NUMERIC_HOST.match(host)


def _parse(url: str) -> tuple[str, str, int]:
    """Return (scheme, host, port) or raise EgressError(invalid_url)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
        scheme = parts.scheme.lower()
    except ValueError as exc:
        raise EgressError(INVALID_URL, str(exc)) from exc
    if scheme not in ("http", "https") or not host:
        raise EgressError(INVALID_URL, "unsupported or missing scheme/host")
    return scheme, host, port if port is not None else (443 if scheme == "https" else 80)


def _classify(exc: BaseException) -> str:
    if isinstance(exc, EgressError):
        return exc.error_type
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException)):
        return TIMEOUT
    if isinstance(exc, socket.gaierror):
        return DNS_FAILURE
    if isinstance(exc, (ConnectionRefusedError, httpx.ConnectError)):
        return CONNECTION_REFUSED
    return OTHER


async def _fetch(scheme: str, host: str, port: int, ip: str, url: str,
                 transport: Optional[httpx.AsyncBaseTransport]) -> FetchResult:
    parts = urlsplit(url)
    ip_host = f"[{ip}]" if ":" in ip else ip
    path = parts.path or "/"
    target = f"{scheme}://{ip_host}:{port}{path}" + (f"?{parts.query}" if parts.query else "")
    host_header = parts.netloc.rpartition("@")[2]  # original Host, userinfo stripped
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_S, follow_redirects=False,
                                 transport=transport, verify=True) as client:
        async with client.stream("GET", target, headers={"Host": host_header},
                                 extensions={"sni_hostname": host}) as resp:
            raw = bytearray()
            async for chunk in resp.aiter_bytes():
                raw.extend(chunk)
                if len(raw) >= PREVIEW_CHARS * 4:
                    break
            text = bytes(raw).decode(resp.encoding or "utf-8", errors="replace")
            return FetchResult(resp.status_code, text[:PREVIEW_CHARS])


async def safe_fetch(url: str, state: Optional[MutableMapping[str, Any]] = None, *,
                     ground_truth: Optional[GroundTruth] = None,
                     resolver: Optional[Resolver] = None,
                     transport: Optional[httpx.AsyncBaseTransport] = None,
                     emitter_fn: Optional[Callable[[dict], None]] = None) -> FetchResult:
    """Fetch ``url`` and return status plus the first 4096 characters of the body.

    ``state`` is the per-request state dict (``request.state``): ``trace_id``,
    ``source_ip``, ``user_id``, ``tenant_id`` and ``endpoint_template`` are read for
    denormalization and ``egress_count`` is incremented. Raises ``EgressError`` on failure.
    """
    state = state if state is not None else {}
    start = datetime.now(timezone.utc)
    t0 = time.perf_counter_ns()
    state["egress_count"] = int(state.get("egress_count") or 0) + 1

    host: Optional[str] = None
    port: Optional[int] = None
    ip: Optional[str] = None
    status: Optional[int] = None
    error_type: Optional[str] = None
    try:
        try:
            scheme, host, port = _parse(url)
        except EgressError:
            raise

        async def run() -> FetchResult:
            nonlocal ip
            ip = await (resolver or _default_resolver)(host, port)
            return await _fetch(scheme, host, port, ip, url, transport)

        try:
            result = await asyncio.wait_for(run(), timeout=FETCH_TIMEOUT_S)
        except EgressError:
            raise
        except BaseException as exc:
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                error_type = OTHER
                raise
            raise EgressError(_classify(exc), str(exc)) from exc
        status = result.status_code
        return result
    except EgressError as exc:
        error_type = exc.error_type
        raise
    finally:
        try:
            duration_ns = time.perf_counter_ns() - t0
            event = EgressEvent(
                trace_id=str(state.get("trace_id") or ""),
                source_ip=str(state.get("source_ip") or "0.0.0.0"),
                start=start,
                duration_ns=duration_ns,
                destination_address=host if host else url,
                url_full=url,
                outcome="success" if error_type is None and status is not None else "failure",
                destination_domain=host if host and _is_domain(host) else None,
                destination_port=port,
                destination_ip=ip,
                status_code=status,
                error_type=error_type,
                user_id=state.get("user_id"),
                tenant_id=state.get("tenant_id"),
                endpoint_template=state.get("endpoint_template"),
                ground_truth=ground_truth or GroundTruth(),
            )
            (emitter_fn or emit_event)(event.to_attributes())
        except Exception:
            pass  # telemetry must never fail the request
