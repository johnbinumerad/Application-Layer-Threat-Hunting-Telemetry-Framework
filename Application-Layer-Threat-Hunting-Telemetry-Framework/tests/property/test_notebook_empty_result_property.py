"""Property 35: Empty-result notebook handling.

Feature: application-layer-threat-hunting-framework, Property 35: Empty-result notebook handling

**Validates: Requirements 12.8**
"""
import contextlib
import io
import os
import sys
from unittest import mock

from hypothesis import given, strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "notebooks"))
import lab_common  # noqa: E402


class _EmptyClient:
    """Minimal SIEM stand-in whose searches always match nothing."""

    def __init__(self, response):
        self._response = response

    def ping(self, **kwargs):
        return True

    def search(self, **kwargs):
        return self._response


_EMPTY_RESPONSES = [
    {"hits": {"total": {"value": 0}, "hits": []}},
    {"hits": {"hits": []}, "aggregations": {}},
    {"hits": {"hits": []}, "aggregations": {"by_user": {"buckets": []}}},
    {},
]

_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=40
)


@given(scenario=_text, time_range=_text, response=st.sampled_from(_EMPTY_RESPONSES))
def test_empty_result_returns_none_with_message_and_no_chart(scenario, time_range, response):
    buf = io.StringIO()
    with mock.patch.object(lab_common, "SIEM_UP", True), mock.patch.object(
        lab_common, "CLIENT", _EmptyClient(response)
    ), contextlib.redirect_stdout(buf):
        result = lab_common.run_query(scenario, {"query": {"match_all": {}}}, time_range)
    out = buf.getvalue()

    assert result is None
    assert scenario in out and time_range in out
    assert lab_common.plot_timeseries(result, x="a", y="b") is None
    assert lab_common.plot_bar(result, x="a", y="b") is None
    assert lab_common.highlight_private(result, "destination.ip") is None
