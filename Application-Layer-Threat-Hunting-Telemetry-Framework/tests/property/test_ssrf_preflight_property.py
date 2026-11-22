"""Property 23: SSRF pre-flight.

**Validates: Requirements 8.8**

For any combination of probe results for the gateway, the Target_API and the metadata
service, the SSRF_Simulator proceeds iff all are reachable; otherwise it exits non-zero,
names an unreachable component and sends no SSRF requests.
"""
import httpx
from hypothesis import given, settings, strategies as st

from labcommon.safety import GatewayConfig
from simulators import hunt_03_ssrf_egress as hunt03
from simulators.common import GroundTruth, SimClient

GW = GatewayConfig("127.0.0.1", 8080, "http")


def _make_client(gateway_up, api_up, meta_up, seen):
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        if req.url.path == hunt03.LAB_STATUS_PATH:
            if not gateway_up:
                raise httpx.ConnectError("gateway down")
            if not api_up:
                return httpx.Response(502, json={"error": "bad gateway"})
            return httpx.Response(200, json={"metadata_service": "up" if meta_up else "down"})
        return httpx.Response(200, text="ok")

    return SimClient(
        "http://127.0.0.1:8080",
        GroundTruth("attack", hunt03.SCENARIO, role="attack_action"),
        run_id="r1", gateway=GW, resolver=lambda h, p: ["127.0.0.1"],
        transport=httpx.MockTransport(handler),
    )


@settings(max_examples=50, deadline=None)
@given(st.booleans(), st.booleans(), st.booleans(), st.sampled_from(["low-and-slow", "noisy"]))
def test_preflight_proceeds_iff_all_reachable(gateway_up, api_up, meta_up, mode):
    seen: list = []
    client = _make_client(gateway_up, api_up, meta_up, seen)
    original = hunt03.SimClient
    hunt03.SimClient = lambda *a, **k: client  # main() builds its own client
    original_delays = dict(hunt03.MODE_DELAY_S)
    hunt03.MODE_DELAY_S.update({"low-and-slow": 0.0, "noisy": 0.0})
    import io
    import contextlib
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = hunt03.main(["--mode", mode])
    finally:
        hunt03.SimClient = original
        hunt03.MODE_DELAY_S.update(original_delays)

    ssrf_requests = [s for s in seen if s[1] == hunt03.PREVIEW_PATH]
    if gateway_up and api_up and meta_up:
        assert code == 0
        assert len(ssrf_requests) == len(hunt03.build_payloads())
    else:
        assert code != 0
        assert ssrf_requests == []
        message = err.getvalue().lower()
        if not gateway_up:
            assert "gateway" in message
        elif not api_up:
            assert "target-api" in message
        else:
            assert "metadata service" in message
