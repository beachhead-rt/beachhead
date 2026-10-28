"""Time-based filtering for store queries (CLI --since and TUI time dropdown)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

TIME_PRESETS: list[tuple[str, str]] = [
    ("All time", "all"),
    ("Last 24 hours", "24h"),
    ("Last 7 days", "7d"),
    ("Last 30 days", "30d"),
    ("Last 90 days", "90d"),
    ("This month", "this-month"),
    ("This year", "this-year"),
    ("Last 365 days", "365d"),
]

SINCE_HELP = "Time filter (e.g. 24h, 7d, 30d, 90d, 1y, this-month, this-year)."

_UNIT_SECONDS: dict[str, int] = {
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def parse_since(value: str) -> datetime | None:
    """Parse a --since value into a UTC cutoff datetime.

    Accepts: 24h, 7d, 30d, 90d, 365d, 1y, this-month, this-year, all.
    Returns None for "all" or unrecognised input.
    """
    value = value.strip().lower()
    if value in ("all", ""):
        return None

    now = datetime.now(UTC)

    if value == "this-month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    if value == "this-year":
        return now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

    for suffix, seconds in _UNIT_SECONDS.items():
        if value.endswith(suffix):
            try:
                n = int(value[: -len(suffix)])
            except ValueError:
                return None
            return now - timedelta(seconds=n * seconds)

    if value.endswith("y"):
        try:
            n = int(value[:-1])
        except ValueError:
            return None
        return now - timedelta(days=n * 365)

    return None


def filter_by_time[T](
    rows: list[T],
    since: datetime | None,
    timestamp_attr: str = "collected_at",
) -> list[T]:
    """Keep only rows whose timestamp is at or after *since*."""
    if since is None:
        return rows
    result: list[T] = []
    for r in rows:
        ts_str = getattr(r, timestamp_attr, None) or ""
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(str(ts_str))
            if ts >= since:
                result.append(r)
        except (ValueError, TypeError):
            result.append(r)
    return result
