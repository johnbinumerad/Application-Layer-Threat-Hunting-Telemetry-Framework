"""Unit tests for simulators.common."""
import json

import httpx
import pytest

from labcommon.safety import GatewayConfig
from simulators.common import GroundTruth, Ledger, SimClient

GW = GatewayConfig("127.0.0.1", 8080, "http")
res = lambda h, p: ["127.0.0.1"]


def _client(tmp_path, handler):
    return SimClient("http://127.0.0.1:8080", GroundTruth("attack", "bola", "bola", "attacker"),
                     run_id="r1", ledger=Ledger(tmp_path / "l.jsonl"), gateway=GW, resolver=res,
                     transport=httpx.MockTransport(handler))


def test_headers_and_ledger(tmp_path):
    seen = []

    def h(req):
        seen.append(req)
        return httpx.Response(200, json={"access_token": "tok"})

    c = _client(tmp_path, h)
    assert c.login("u", "pw", source_ip="198.51.100.77") == "tok"
    r = seen[0].headers
    assert r["x-lab-label"] == "attack" and r["x-lab-scenario"] == "bola"
    assert r["x-lab-run-id"] == "r1" and r["x-lab-role"] == "attacker"
    assert r["x-forwarded-for"] == "198.51.100.77"
    lines = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text().splitlines()]
    assert {x["kind"] for x in lines} == {"password", "token"}


def test_outside_lab_sends_nothing(tmp_path, capsys):
    called = []
    with pytest.raises(SystemExit) as e:
        SimClient("http://example.com:8080", GroundTruth("baseline", "b"), gateway=GW,
                  resolver=lambda h, p: ["93.184.216.34"],
                  transport=httpx.MockTransport(lambda r: called.append(r)))
    assert e.value.code == 2 and not called
    assert "outside the Lab" in capsys.readouterr().err
