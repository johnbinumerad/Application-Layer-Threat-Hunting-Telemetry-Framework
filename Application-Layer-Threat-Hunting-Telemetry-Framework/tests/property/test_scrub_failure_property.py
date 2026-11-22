"""Property 14: Scrub failure fails closed.

**Validates: Requirements 4.5**

For any batch where some records cannot be scrubbed (unsupported attribute
types), no part of a failed record reaches the SIEM-bound output, the failure
counter increases by exactly the number of failed records, and the log
entries contain only the record identifiers.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from labcommon.scrub_model import (
    AUTH_KEY,
    PASSWORD_KEY,
    ScrubberModel,
    is_sealed,
)

SALT = "test-salt"

_ids = st.uuids().map(str)
_secret = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=12, max_size=24)
_bad_values = st.one_of(
    st.binary(min_size=1, max_size=8),
    st.just(object()),
    st.builds(set, st.lists(st.integers(), max_size=3)),
    st.builds(lambda b: [b], st.binary(min_size=1, max_size=4)),
)


@st.composite
def record_spec(draw):
    """Returns (record, should_fail, secret)."""
    event_id = draw(_ids)
    # unique per record so a failed record's secret cannot legitimately
    # appear in another (successfully scrubbed) record's output
    secret = "SECRET" + draw(_secret) + event_id.replace("-", "")
    rec = {
        "event.id": event_id,
        "trace.id": draw(_ids),
        "http.request.method": "GET",
        "url.full": f"http://x.test/?note={secret}",
        "appsec.note": f"free text {secret}",
        PASSWORD_KEY: secret,
        AUTH_KEY: "Bearer " + secret,
    }
    fail = draw(st.booleans())
    if fail:
        rec["appsec.unsupported"] = draw(_bad_values)
    return rec, fail, secret


@settings(max_examples=100, deadline=None)
@given(specs=st.lists(record_spec(), min_size=0, max_size=12), prior=st.integers(0, 5))
def test_scrub_failure_fails_closed(specs, prior):
    model = ScrubberModel(SALT)
    model.failure_count = prior
    records = [s[0] for s in specs]
    failed_specs = [s for s in specs if s[1]]
    ok_specs = [s for s in specs if not s[1]]

    result = model.process(records)

    # counter increases by exactly the number of failed records
    assert result.failure_count == prior + len(failed_specs)
    assert model.failure_count == prior + len(failed_specs)
    assert len(result.failed) == len(failed_specs)
    assert len(result.log) == len(failed_specs)

    # only sealed records are exported, one per good record
    assert len(result.exported) == len(ok_specs)
    assert all(is_sealed(r) for r in result.exported)
    exported_ids = {r["event.id"] for r in result.exported}
    failed_ids = {rec["event.id"] for rec, _, _ in failed_specs}
    assert not (exported_ids & failed_ids)

    # nothing from a failed record reaches the output or log other than ids
    blob_out = repr(result.exported)
    blob_failed = repr(result.failed) + repr(result.log)
    for rec, fail, secret in specs:
        assert secret not in blob_failed
        if fail:
            assert secret not in blob_out
    for entry in result.failed:
        assert set(entry) <= {"event.id", "trace.id"}
    for n, entry in result.log:
        assert set(entry) <= {"event.id", "trace.id"}

    # log counter values count up by exactly 1 per failure
    assert [n for n, _ in result.log] == list(
        range(prior + 1, prior + len(failed_specs) + 1)
    )
    # log identifiers match the failed records in order
    assert [e.get("event.id") for _, e in result.log] == [
        rec["event.id"] for rec, _, _ in failed_specs
    ]


def test_unsupported_type_example_is_dropped():
    model = ScrubberModel(SALT)
    rec = {"event.id": "e1", "trace.id": "t1", "x": b"raw", PASSWORD_KEY: "hunter2hunter2"}
    res = model.process([rec])
    assert res.exported == []
    assert res.failed == [{"event.id": "e1", "trace.id": "t1"}]
    assert res.log == [(1, {"event.id": "e1", "trace.id": "t1"})]
