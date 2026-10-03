"""Framework-neutral rate-limit contracts for authentication security boundaries."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from pyiamkit.shared import Clock

from .domain.errors import AuthenticationError


class RateLimitError(AuthenticationError):
    """Base error for authentication rate-limit enforcement."""

    code = "RATE_LIMIT_ERROR"


class RateLimitExceeded(RateLimitError):
    """Raised when a configured rate-limit bucket denies the operation."""

    code = "RATE_LIMIT_EXCEEDED"


class RateLimitUnavailable(RateLimitError):
    """Raised when the rate-limit authority cannot provide a trustworthy decision."""

    code = "RATE_LIMIT_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class RateLimitKey:
    """Opaque, namespaced key used to isolate independent rate-limit buckets."""

    namespace: str
    subject: str

    def __post_init__(self) -> None:
        namespace = self.namespace.strip().lower()
        subject = self.subject.strip()
        if not namespace:
            raise ValueError("RateLimitKey.namespace must not be empty")
        if not subject:
            raise ValueError("RateLimitKey.subject must not be empty")
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "subject", subject)


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Bounded consumption policy interpreted atomically by a RateLimiter."""

    limit: int
    window: timedelta

    def __post_init__(self) -> None:
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or self.limit < 1:
            raise ValueError("RateLimitPolicy.limit must be an integer >= 1")
        if self.window <= timedelta(0):
            raise ValueError("RateLimitPolicy.window must be positive")


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """One atomic rate-limit consumption decision."""

    allowed: bool
    remaining: int
    retry_after: timedelta | None = None

    def __post_init__(self) -> None:
        if isinstance(self.remaining, bool) or not isinstance(self.remaining, int):
            raise ValueError("RateLimitDecision.remaining must be an integer")
        if self.remaining < 0:
            raise ValueError("RateLimitDecision.remaining must be >= 0")
        if self.allowed and self.retry_after is not None:
            raise ValueError("Allowed RateLimitDecision must not define retry_after")
        if not self.allowed and (self.retry_after is None or self.retry_after <= timedelta(0)):
            raise ValueError("Denied RateLimitDecision requires positive retry_after")


class RateLimiter(Protocol):
    """Atomic external rate-limit authority.

    Implementations may use local memory, Redis, a gateway, or another backend, but
    the decision must atomically observe and consume the requested cost.
    """

    def check_and_consume(
        self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
        *,
        at: datetime,
        cost: int = 1,
    ) -> RateLimitDecision: ...


class RateLimitGuard:
    """Fail-closed orchestration around a framework-neutral RateLimiter."""

    def __init__(self, *, limiter: RateLimiter, clock: Clock) -> None:
        self._limiter = limiter
        self._clock = clock

    def require(
        self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
        *,
        cost: int = 1,
    ) -> RateLimitDecision:
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 1:
            raise ValueError("rate-limit cost must be an integer >= 1")

        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise RateLimitUnavailable("Rate-limit clock must return a UTC-aware datetime")

        decision = self._limiter.check_and_consume(
            key,
            policy,
            at=now,
            cost=cost,
        )
        if not decision.allowed:
            raise RateLimitExceeded(
                f"Rate limit exceeded for namespace {key.namespace!r}; "
                f"retry after {decision.retry_after}"
            )
        return decision
