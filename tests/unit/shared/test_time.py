from datetime import timezone

from pyiamkit.shared import SystemClock


def test_system_clock_returns_timezone_aware_utc_datetime() -> None:
    now = SystemClock().now()

    assert now.tzinfo is not None
    assert now.utcoffset() == timezone.utc.utcoffset(now)
