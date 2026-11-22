"""Command-line parameter validation and --mode preset resolution (Req 5.4, 5.5, 6.3, 7.1-7.3)."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

DURATION_RANGE = (1, 86_400)
RATE_RANGE = (1, 1_000)
JWT_COUNT_RANGE = (1, 1_000)
JWT_HIJACK_RANGE = (2, 1_000)
BOLA_START_ID_RANGE = (1, 2**31 - 1)
BOLA_COUNT_RANGE = (1, 100_000)
MODES = ("low-and-slow", "noisy")
DEFAULT_MODE = "low-and-slow"

# Mode only selects defaults; explicit values override and are still validated.
MODE_PRESETS: dict[str, dict[str, float]] = {
    "low-and-slow": {"rate": 0.5, "jwt_count": 5, "bola_count": 80},
    "noisy": {"rate": 50, "jwt_count": 50, "bola_count": 500},
}


class ParamError(ValueError):
    """Invalid parameter; `param` names the offender."""

    def __init__(self, param: str, message: str):
        self.param = param
        super().__init__(f"invalid parameter --{param.replace('_', '-')}: {message}")


def parse_int(name: str, value: Any, lo: int, hi: int) -> int:
    """Accept only a real integer (or integer string) within [lo, hi]."""
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise ParamError(name, "missing")
    if isinstance(value, bool):
        raise ParamError(name, "must be an integer")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        s = value.strip()
        body = s[1:] if s[:1] in "+-" else s
        if not (body.isascii() and body.isdigit()):
            raise ParamError(name, f"{value!r} is not an integer")
        n = int(s)
    else:
        raise ParamError(name, f"{value!r} is not an integer")
    if not lo <= n <= hi:
        raise ParamError(name, f"{n} is outside the allowed range {lo}-{hi}")
    return n


def parse_rate(name: str, value: Any, lo: float, hi: float) -> float:
    """Positive finite number (used for BOLA rate, which may be fractional)."""
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise ParamError(name, "missing")
    if isinstance(value, bool):
        raise ParamError(name, "must be a number")
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ParamError(name, f"{value!r} is not a number") from None
    if not math.isfinite(f):
        raise ParamError(name, f"{value!r} is not a finite number")
    if not lo <= f <= hi:
        raise ParamError(name, f"{f} is outside the allowed range {lo}-{hi}")
    return f


def validate_duration(value: Any) -> int:
    return parse_int("duration", value, *DURATION_RANGE)


def validate_rate(value: Any) -> int:
    return parse_int("rate", value, *RATE_RANGE)


def validate_jwt_count(name: str, value: Any) -> int:
    """name is one of alg_none_count / expired_count (1-1000)."""
    return parse_int(name, value, *JWT_COUNT_RANGE)


def validate_jwt_hijack_count(value: Any, name: str = "hijack_count") -> int:
    return parse_int(name, value, *JWT_HIJACK_RANGE)


def resolve_mode(mode: str | None) -> str:
    m = DEFAULT_MODE if mode is None else mode
    if m not in MODES:
        raise ParamError("mode", f"{m!r} must be one of {', '.join(MODES)}")
    return m


@dataclass(frozen=True)
class BolaParams:
    mode: str
    rate: float
    start_id: int
    count: int


def resolve_bola(args: Mapping[str, Any], default_start_id: int = 1011) -> BolaParams:
    """Explicit values override mode presets; every effective value is validated."""
    mode = resolve_mode(args.get("mode"))
    preset = MODE_PRESETS[mode]
    rate = args.get("rate")
    count = args.get("count")
    start = args.get("start_id")
    return BolaParams(
        mode=mode,
        rate=parse_rate("rate", preset["rate"] if rate is None else rate, 1e-6, RATE_RANGE[1]),
        start_id=parse_int("start_id", default_start_id if start is None else start, *BOLA_START_ID_RANGE),
        count=parse_int("count", preset["bola_count"] if count is None else count, *BOLA_COUNT_RANGE),
    )


@dataclass(frozen=True)
class JwtParams:
    mode: str
    alg_none_count: int
    expired_count: int
    hijack_count: int


def resolve_jwt(args: Mapping[str, Any]) -> JwtParams:
    mode = resolve_mode(args.get("mode"))
    default = int(MODE_PRESETS[mode]["jwt_count"])

    def pick(key: str):
        v = args.get(key)
        return default if v is None else v

    return JwtParams(
        mode=mode,
        alg_none_count=validate_jwt_count("alg_none_count", pick("alg_none_count")),
        expired_count=validate_jwt_count("expired_count", pick("expired_count")),
        hijack_count=validate_jwt_hijack_count(pick("hijack_count")),
    )


@dataclass(frozen=True)
class BaselineParams:
    duration: int
    rate: int


def resolve_baseline(args: Mapping[str, Any]) -> BaselineParams:
    """Duration and rate are required (no defaults)."""
    return BaselineParams(
        duration=validate_duration(args.get("duration")),
        rate=validate_rate(args.get("rate")),
    )
