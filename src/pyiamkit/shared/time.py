"""Time abstractions used by the domain."""

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    """Source of timezone-aware timestamps."""

    def now(self) -> datetime:
        """Return the current time."""

        ...


class SystemClock:
    """Production clock using UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)
