"""Unit tests for simulators.hunt_03_ssrf_egress."""
import httpx
import pytest

from labcommon.safety import GatewayConfig
from simulators import hunt_03_ssrf_egress as hunt03
from simulators.common import GroundTruth, SimClient

GW = GatewayConfig("127.0.0.1", 8080, "http")
RESOLVE_LOCAL = lambda h, p: ["127.0.0.1"]


def _client(tmp_path, handler):
    return SimClient(
        "http://127.0.0.1:8080",
        GroundTruth("attack", hunt03.SCENARIO, role="attack_action"),
        run_id="r1",
        gateway=GW,
        resolver=RESOLVE_LOCAL,
        transport=httpx.MockTransport(handler),
    )


def test_build_payloads_covers_required_techniques():
    payloads = hunt03.build_payloads()
    # Req 8.1: at least 1 metadata URL and at least 1 internal-service URL.
    assert sum(p.name == "metadata_service" for p in payloads) >= 1
    assert sum(p.name == "internal_service" for p in payloads) >= 1
    # Req 8.4: at least 1 alternate IP encoding and at least 1 DNS-alias URL.
    assert sum(p.name == "alt_encoding" for p in payloads) >= 1
    assert sum(p.name == "dns_alias" for p in payloads) >= 1
    assert all(p.url for p in payloads)


def test_preflight_passes_when_all_components_up(tmp_path):
    def handler(req):
        assert req.url.path == hunt03.LAB_STATUS_PATH
        return httpx.Response(200, json={"metadata_service": "up"})

    client = _client(tmp_path, handler)
    hunt03.preflight(client)  # does not raise
    client.close()


@pytest.mark.parametrize("status,body,expect_in_message", [
    (503, {"metadata_service": "up"}, "target-api unreachable"),
    (200, {"metadata_service": "down"}, "metadata service unreachable"),
])
def test_preflight_fails_and_names_component(tmp_path, status, body, expect_in_message):
    def handler(req):
        return httpx.Response(status, json=body)

    client = _client(tmp_path, handler)
    with pytest.raises(hunt03.PreflightError) as e:
        hunt03.preflight(client)
    assert expect_in_message in str(e.value)
    client.close()


def test_preflight_fails_when_gateway_unreachable(tmp_path):
    def handler(req):
        raise httpx.ConnectError("refused")

    client = _client(tmp_path, handler)
    with pytest.raises(hunt03.PreflightError) as e:
        hunt03.preflight(client)
    assert "unreachable" in str(e.value)
    client.close()


def test_run_sends_one_request_per_payload_and_counts_canaries(tmp_path):
    seen = []

    def handler(req):
        seen.append(req)
        if "169.254.169.254" in str(req.content):
            return httpx.Response(200, json={"status_code": 200, "body": hunt03.METADATA_CANARY})
        return httpx.Response(200, json={"status_code": 200, "body": hunt03.INTERNAL_CANARY})

    client = _client(tmp_path, handler)
    payloads = hunt03.build_payloads()
    sent, hits = hunt03.run(client, payloads, delay_s=0.0, sleep=lambda s: None)
    client.close()

    assert sent == len(payloads) == len(seen)
    assert hits == len(payloads)
    # Each request is its own POST to the preview endpoint (Req 8.1).
    assert all(r.url.path == hunt03.PREVIEW_PATH for r in seen)


def test_run_counts_requests_sent_even_without_canary(tmp_path):
    def handler(req):
        return httpx.Response(502, json={"error": "bad_gateway"})

    client = _client(tmp_path, handler)
    payloads = hunt03.build_payloads()
    sent, hits = hunt03.run(client, payloads, delay_s=0.0, sleep=lambda s: None)
    client.close()

    assert sent == len(payloads)
    assert hits == 0


def test_main_exits_nonzero_and_sends_nothing_when_preflight_fails(tmp_path, monkeypatch, capsys):
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(503, json={"metadata_service": "down"})

    def fake_init(self, target, ground_truth, run_id=None, ledger=None, gateway=None,
                 resolver=None, transport=None, timeout=10.0, sleep=None):
        from simulators.common import Ledger
        from labcommon import safety as safety_mod
        safety_mod.validate_target(target, GW, RESOLVE_LOCAL)
        self.target = target
        self.ground_truth = ground_truth
        self.run_id = run_id or "r1"
        self.ledger = Ledger(tmp_path / "l.jsonl")
        self._http = httpx.Client(base_url=target, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("simulators.common.SimClient.__init__", fake_init)

    rc = hunt03.main(["--target", "http://127.0.0.1:8080"])
    out = capsys.readouterr()

    assert rc != 0
    assert "unreachable" in out.err or "down" in out.err
    # Only the pre-flight status call was made; zero SSRF requests were sent.
    assert len(calls) == 1
