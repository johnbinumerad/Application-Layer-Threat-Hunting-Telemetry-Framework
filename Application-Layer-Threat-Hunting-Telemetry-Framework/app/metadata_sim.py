"""Simulated cloud instance-metadata service (IMDS style) for the SSRF scenario.

Binds ``169.254.169.254:80`` on the container loopback (the entrypoint adds the
address to ``lo``). All data is fake; credentials are lab-only placeholders and
the credentials document carries ``LAB-METADATA-CANARY``.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

META_HOST = "169.254.169.254"
META_PORT = 80
METADATA_CANARY = "LAB-METADATA-CANARY"
ROLE = "lab-role"

CREDENTIALS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIALABFAKE000000000",
    "SecretAccessKey": "lab-fake-secret-access-key/" + METADATA_CANARY,
    "Token": "lab-fake-session-token-" + METADATA_CANARY,
    "Expiration": "2099-01-01T00:00:00Z",
    "Canary": METADATA_CANARY,
}

_TEXT = "text/plain"
_JSON = "application/json"

ROUTES: dict[str, tuple[str, str]] = {
    "/": (_TEXT, "latest\n"),
    "/latest": (_TEXT, "meta-data\n"),
    "/latest/meta-data": (_TEXT, "ami-id\ninstance-id\nhostname\niam/\n"),
    "/latest/meta-data/ami-id": (_TEXT, "ami-0labfake0000000"),
    "/latest/meta-data/instance-id": (_TEXT, "i-0labfake00000000"),
    "/latest/meta-data/hostname": (_TEXT, "ip-172-28-0-10.lab.internal"),
    "/latest/meta-data/iam": (_TEXT, "security-credentials/\n"),
    "/latest/meta-data/iam/security-credentials": (_TEXT, ROLE + "\n"),
    "/latest/meta-data/iam/security-credentials/" + ROLE: (
        _JSON, json.dumps(CREDENTIALS, indent=2)),
}


class MetadataHandler(BaseHTTPRequestHandler):
    server_version = "LabIMDS/1.0"

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if len(path) > 1:
            path = path.rstrip("/")
        route = ROUTES.get(path)
        if route is None:
            body, ctype, status = b"not found", _TEXT, 404
        else:
            ctype, text = route
            body, status = text.encode(), 200
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silence stderr access log
        return


def make_server(host: str = META_HOST, port: int = META_PORT) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MetadataHandler)
    server.daemon_threads = True
    return server


def start_in_thread(host: str = META_HOST, port: int = META_PORT) -> Optional[ThreadingHTTPServer]:
    """Start the service in a daemon thread; return None if the bind fails."""
    try:
        server = make_server(host, port)
    except OSError:
        return None
    threading.Thread(target=server.serve_forever, name="metadata-sim", daemon=True).start()
    return server


if __name__ == "__main__":  # pragma: no cover
    make_server().serve_forever()
