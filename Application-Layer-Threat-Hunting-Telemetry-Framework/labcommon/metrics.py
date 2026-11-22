"""Validation metrics (TP/FP/FN/precision) over labelled ground-truth events.

Pure logic. Events are mappings with at least ``event_id``, ``label``
(``"attack"`` or ``"baseline"``) and optionally ``role`` (``"setup"`` events
are excluded from FN).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

ATTACK = "attack"
BASELINE = "baseline"
SETUP_ROLE = "setup"
NOT_APPLICABLE = "not applicable"


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    fn: int
    precision: float | str  # percentage rounded to 1 dp, or "not applicable"

    def as_dict(self) -> dict[str, Any]:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "precision": self.precision}


def precision_percent(tp: int, fp: int) -> float | str:
    """TP / (TP + FP) * 100 rounded half-up to one decimal, or "not applicable"."""
    denom = tp + fp
    if denom == 0:
        return NOT_APPLICABLE
    pct = Decimal(tp) * 100 / Decimal(denom)
    return float(pct.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def compute_metrics(
    events: Iterable[Mapping[str, Any]],
    alerted_event_ids: Iterable[str],
) -> Metrics:
    """Compute TP/FP/FN/precision.

    TP: alerted events labelled attack. FP: alerted events labelled baseline.
    FN: attack-labelled, non-setup-role events that were not alerted.
    Alerted ids not present in ``events`` are ignored.
    """
    alerted = set(alerted_event_ids)
    tp = fp = fn = 0
    seen: set[str] = set()
    for ev in events:
        eid = ev.get("event_id")
        if eid in seen:
            continue
        seen.add(eid)
        label = ev.get("label")
        hit = eid in alerted
        if label == ATTACK:
            if hit:
                tp += 1
            elif ev.get("role") != SETUP_ROLE:
                fn += 1
        elif label == BASELINE and hit:
            fp += 1
    return Metrics(tp, fp, fn, precision_percent(tp, fp))
