"""Deterministic request schedule keeping every rolling 60 s window <= rate (Req 6.2)."""
from __future__ import annotations

from fractions import Fraction

WINDOW_S = 60


def request_offsets(count: int, rate: float) -> list[float]:
    """Return send offsets (seconds from start) for `count` requests.

    Requests are evenly spaced at 1/rate seconds, starting at t=0. Any rolling 60 s
    window [t, t+60) then holds at most ceil(60*rate) requests, and the average over
    a 60 s window never exceeds `rate` once spacing is applied (a window of length
    W holds at most floor(W*rate)+1 events; we additionally enforce the cap below by
    delaying the first request of each over-full window).
    """
    if count < 0:
        raise ValueError("count must be >= 0")
    if not rate > 0:
        raise ValueError("rate must be > 0")
    fr = Fraction(rate).limit_denominator(10**9)
    cap = int(fr * WINDOW_S)  # max requests in any 60 s window (average <= rate)
    # 1 ns of slack keeps the bound true after float conversion.
    spacing = Fraction(1) / fr + Fraction(1, 10**9)
    offsets: list[Fraction] = []
    t = Fraction(0)
    for i in range(count):
        if cap >= 1 and i >= cap:
            # The request `cap` positions back must be at least 60 s old.
            t = max(t, offsets[i - cap] + WINDOW_S)
        offsets.append(t)
        t += spacing
    return [float(o) for o in offsets]


def max_in_window(offsets: list[float], window: float = WINDOW_S) -> int:
    """Largest number of requests in any half-open window [t, t+window)."""
    best, lo = 0, 0
    for hi, t in enumerate(offsets):
        while t - offsets[lo] >= window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best
