"""Property 7: Event schema and field mapping (builders).

Feature: application-layer-threat-hunting-framework, Property 7

**Validates: Requirements 3.2, 3.3, 3.4, 3.5**
"""
import json
import re
from datetime import datetime, timedelta, timezone

from hypothesis import given, strategies as st

from labcommon.schema import EgressEvent, GroundTruth, TelemetryEvent, load_field_mapping

MAPPING_KEYS = set(load_field_mapping()["fields"].keys())
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
TEMPLATE = "/api/v1/invoices/{invoice_id}"

text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=40)
opt_text = st.one_of(st.none(), text)  # includes "" which must be omitted
datetimes = st.datetimes(
    min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1),
    timezones=st.sampled_from([timezone.utc, timezone(timedelta(hours=5, minutes=30)),
                               timezone(timedelta(hours=-8))]),
)
naive_or_aware = st.one_of(datetimes, st.datetimes(min_value=datetime(2000, 1, 1)))
durations = st.integers(min_value=-10**6, max_value=10**13)
ground_truth = st.builds(GroundTruth, label=opt_text, scenario=opt_text, technique=opt_text,
                         run_id=opt_text, role=opt_text)
ids = st.integers(min_value=0, max_value=10**6)


@st.composite
def telemetry_events(draw):
    return TelemetryEvent(
        trace_id=draw(st.text(min_size=1, max_size=36)),
        source_ip=draw(st.ip_addresses().map(str)),
        start=draw(naive_or_aware),
        duration_ns=draw(durations),
        action=draw(st.sampled_from(["api_request", "auth_login", "jwt_validation_failed"])),
        outcome=draw(st.sampled_from(["success", "failure"])),
        method=draw(st.sampled_from(["GET", "POST", "PUT", "DELETE"])),
        status_code=draw(st.integers(100, 599)),
        path=draw(st.one_of(text.map(lambda s: "/" + s), ids.map(lambda i: f"/api/v1/invoices/{i}"))),
        endpoint_template=draw(st.sampled_from([TEMPLATE, "unmatched", "/api/v1/auth/login"])),
        egress_count=draw(st.integers(-5, 50)),
        user_agent=draw(st.one_of(opt_text, st.text(min_size=513, max_size=1500))),
        user_id=draw(opt_text),
        user_roles=draw(st.lists(text, max_size=3)),
        tenant_id=draw(opt_text),
        resource_id=draw(st.one_of(st.none(), text, ids.map(str))),
        jwt_jti=draw(opt_text),
        jwt_alg=draw(opt_text),
        jwt_exp=draw(st.one_of(st.none(), datetimes)),
        jwt_expired=draw(st.one_of(st.none(), st.booleans())),
        jwt_verified=draw(st.one_of(st.none(), st.booleans())),
        resource_tenant_id=draw(opt_text),
        cross_tenant=draw(st.one_of(st.none(), st.booleans())),
        ground_truth=draw(ground_truth),
    )


@st.composite
def egress_events(draw):
    return EgressEvent(
        trace_id=draw(st.text(min_size=1, max_size=36)),
        source_ip=draw(st.ip_addresses().map(str)),
        start=draw(naive_or_aware),
        duration_ns=draw(durations),
        destination_address=draw(st.text(min_size=1, max_size=40)),
        url_full=draw(st.text(min_size=1, max_size=80)),
        outcome=draw(st.sampled_from(["success", "failure"])),
        destination_domain=draw(opt_text),
        destination_port=draw(st.one_of(st.none(), st.integers(1, 65535))),
        destination_ip=draw(st.one_of(st.none(), st.ip_addresses().map(str))),
        status_code=draw(st.one_of(st.none(), st.integers(100, 599))),
        error_type=draw(st.one_of(st.none(), st.just(""), st.sampled_from(
            ["dns_failure", "connection_refused", "timeout", "invalid_url", "other"]))),
        user_id=draw(opt_text),
        tenant_id=draw(opt_text),
        endpoint_template=draw(st.one_of(st.none(), st.just(TEMPLATE))),
        ground_truth=draw(ground_truth),
    )


def _check_common(attrs):
    # single valid JSON object round trip
    decoded = json.loads(json.dumps(attrs))
    assert isinstance(decoded, dict) and decoded == attrs
    assert TS_RE.match(attrs["@timestamp"])
    assert isinstance(attrs["appsec.latency_ms"], int)
    assert not isinstance(attrs["appsec.latency_ms"], bool)
    assert attrs["appsec.latency_ms"] >= 0
    assert set(attrs) <= MAPPING_KEYS, set(attrs) - MAPPING_KEYS
    for key, value in attrs.items():
        assert value != "", key
        assert value is not None, key
        assert value != [], key
    if "user_agent.original" in attrs:
        assert len(attrs["user_agent.original"]) <= 512


@given(telemetry_events())
def test_api_event_schema_and_mapping(ev):
    attrs = ev.to_attributes()
    _check_common(attrs)
    # omission of unavailable fields
    for key, value in (("user.id", ev.user_id), ("organization.id", ev.tenant_id),
                       ("appsec.jwt.jti", ev.jwt_jti), ("appsec.resource_id", ev.resource_id)):
        assert (key in attrs) == bool(value)
    if ev.resource_id:
        assert attrs["appsec.resource_id"] == ev.resource_id
    assert attrs["appsec.endpoint_template"] == ev.endpoint_template


@given(ids, st.sampled_from(["GET", "PUT", "DELETE"]))
def test_invoice_path_template_constant_and_raw_resource_id(invoice_id, method):
    raw = str(invoice_id)
    ev = TelemetryEvent(
        trace_id="t", source_ip="192.0.2.1", start=datetime.now(timezone.utc), duration_ns=1,
        action="api_request", outcome="success", method=method, status_code=200,
        path=f"/api/v1/invoices/{raw}", endpoint_template=TEMPLATE, resource_id=raw)
    attrs = ev.to_attributes()
    assert attrs["appsec.endpoint_template"] == TEMPLATE
    assert attrs["appsec.resource_id"] == raw


@given(egress_events())
def test_egress_event_schema_and_mapping(ev):
    attrs = ev.to_attributes()
    _check_common(attrs)
    assert attrs["event.dataset"] == "appsec.egress"
    assert ("error.type" in attrs) == bool(ev.error_type)
    assert ("http.response.status_code" in attrs) == (ev.status_code is not None)
