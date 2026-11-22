"""``labctl up``: preflight published ports, then ``docker compose up -d``.

Preflight (Req 1.6, 9.5, 9.6): every published port must bind 127.0.0.1 and be
free on the host. On a violation, name the port/binding, run
``docker compose down`` and exit non-zero.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from collections.abc import Callable, Iterable

LOOPBACK = "127.0.0.1"


def extract_published_ports(config: dict) -> list[dict]:
    """Return ``[{service, host_ip, published, protocol}]`` for every published port.

    Handles the long form emitted by ``docker compose config --format json``
    and, defensively, short-form strings (``"127.0.0.1:8080:8080"``, ``"8080:80"``).
    """
    result: list[dict] = []
    for name, svc in (config.get("services") or {}).items():
        for port in svc.get("ports") or []:
            if isinstance(port, dict):
                published = port.get("published")
                if published in (None, ""):
                    published = None
                result.append(
                    {
                        "service": name,
                        "host_ip": port.get("host_ip") or "",
                        "published": int(published) if published is not None else None,
                        "protocol": port.get("protocol", "tcp"),
                    }
                )
            else:
                spec = str(port).split("/")[0]
                parts = spec.split(":")
                if len(parts) == 3:
                    host_ip, published = parts[0], parts[1]
                elif len(parts) == 2:
                    host_ip, published = "", parts[0]
                else:
                    host_ip, published = "", ""
                result.append(
                    {
                        "service": name,
                        "host_ip": host_ip,
                        "published": int(published) if published.isdigit() else None,
                        "protocol": "tcp",
                    }
                )
    return result


def port_is_free(port: int, host: str = LOOPBACK) -> bool:
    """True if nothing on the host is bound to or listening on ``host:port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def check_ports(
    config: dict,
    busy_check: Callable[[int], bool] | None = None,
) -> list[str]:
    """Return a list of violation messages (empty means the preflight passes).

    ``busy_check(port)`` returns True when the port is free; injectable for tests.
    """
    is_free = busy_check or port_is_free
    errors: list[str] = []
    for p in extract_published_ports(config):
        svc, ip, port = p["service"], p["host_ip"], p["published"]
        binding = f"{ip or '<all interfaces>'}:{port if port is not None else '<random>'}"
        if ip != LOOPBACK:
            errors.append(
                f"service '{svc}' publishes {binding}: binding must be {LOOPBACK} (port {port})"
            )
        if port is not None and not is_free(port):
            errors.append(f"service '{svc}': host port {port} is already in use")
    return errors


def _compose_config() -> dict:
    out = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def run_up(
    config_loader: Callable[[], dict] = _compose_config,
    runner: Callable[[list[str]], int] | None = None,
    busy_check: Callable[[int], bool] | None = None,
    stderr=None,
) -> int:
    """Run the preflight and start the lab. Returns the process exit code."""
    err = stderr or sys.stderr
    run = runner or (lambda argv: subprocess.run(argv).returncode)
    try:
        config = config_loader()
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"labctl up: cannot read compose configuration: {exc}", file=err)
        run(["docker", "compose", "down"])
        return 1
    errors = check_ports(config, busy_check)
    if errors:
        for e in errors:
            print(f"labctl up: preflight failed: {e}", file=err)
        run(["docker", "compose", "down"])
        return 1
    return run(["docker", "compose", "up", "-d"])


def main(argv: Iterable[str] | None = None) -> int:
    return run_up()


if __name__ == "__main__":
    sys.exit(main())
