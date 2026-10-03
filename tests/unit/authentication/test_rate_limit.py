from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import (
    RateLimitDecision,
    RateLimitExceeded,
    RateLimitGuard,
    RateLimitKey,
    RateLimitPolicy,
    RateLimitUnavailable,
)
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 3, 8, 30, tzinfo=UTC)


class FrozenClock(Clock):
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class RecordingLimiter:
    def __init__(self, decision: RateLimitDecision) -> None:
        self.decision = decision
        self.calls: list[tuple[RateLimitKey, RateLimitPolicy, datetime, int]] = []

    def check_and_consume(
        self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
        *,
        at: datetime,
        cost: int = 1,
    ) -> RateLimitDecision:
        self.calls.append((key, policy, at, cost))
        return self.decision


class UnavailableLimiter:
    def check_and_consume(
        self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
        *,
        at: datetime,
        cost: int = 1,
    ) -> RateLimitDecision:
        del key, policy, at, cost
        raise RateLimitUnavailable("rate-limit backend unavailable")


def test_rate_limit_key_and_policy_are_normalized_and_bounded() -> None:
    key = RateLimitKey("  Login.Attempt  ", "  actor-42  ")
    policy = RateLimitPolicy(limit=5, window=timedelta(minutes=1))

    assert key.namespace == "login.attempt"
    assert key.subject == "actor-42"
    assert policy.limit == 5
    assert policy.window == timedelta(minutes=1)


@pytest.mark.parametrize(
    ("limit", "window"),
    [
        (0, timedelta(seconds=1)),
        (-1, timedelta(seconds=1)),
        (True, timedelta(seconds=1)),
        (1, timedelta(0)),
        (1, timedelta(seconds=-1)),
    ],
)
def test_rate_limit_policy_rejects_invalid_bounds(limit: object, window: timedelta) -> None:
    with pytest.raises(ValueError):
        RateLimitPolicy(limit=limit, window=window)  # type: ignore[arg-type]


def test_rate_limit_decision_enforces_retry_semantics() -> None:
    allowed = RateLimitDecision(allowed=True, remaining=3)
    denied = RateLimitDecision(
        allowed=False,
        remaining=0,
        retry_after=timedelta(seconds=30),
    )

    assert allowed.retry_after is None
    assert denied.retry_after == timedelta(seconds=30)

    with pytest.raises(ValueError):
        RateLimitDecision(allowed=True, remaining=1, retry_after=timedelta(seconds=1))
    with pytest.raises(ValueError):
        RateLimitDecision(allowed=False, remaining=0)


def test_rate_limit_guard_consumes_atomically_and_returns_allow_decision() -> None:
    decision = RateLimitDecision(allowed=True, remaining=2)
    limiter = RecordingLimiter(decision)
    guard = RateLimitGuard(limiter=limiter, clock=FrozenClock())
    key = RateLimitKey("authentication.login", "alice")
    policy = RateLimitPolicy(limit=5, window=timedelta(minutes=1))

    result = guard.require(key, policy, cost=2)

    assert result is decision
    assert limiter.calls == [(key, policy, NOW, 2)]


def test_rate_limit_guard_raises_when_limit_is_exceeded() -> None:
    limiter = RecordingLimiter(
        RateLimitDecision(
            allowed=False,
            remaining=0,
            retry_after=timedelta(seconds=20),
        )
    )
    guard = RateLimitGuard(limiter=limiter, clock=FrozenClock())

    with pytest.raises(RateLimitExceeded, match=r"authentication\.login"):
        guard.require(
            RateLimitKey("authentication.login", "alice"),
            RateLimitPolicy(limit=3, window=timedelta(minutes=1)),
        )


def test_rate_limit_guard_fails_closed_when_limiter_is_unavailable() -> None:
    guard = RateLimitGuard(limiter=UnavailableLimiter(), clock=FrozenClock())

    with pytest.raises(RateLimitUnavailable, match="backend unavailable"):
        guard.require(
            RateLimitKey("authentication.login", "alice"),
            RateLimitPolicy(limit=3, window=timedelta(minutes=1)),
        )


def test_rate_limit_guard_fails_closed_for_non_utc_clock() -> None:
    limiter = RecordingLimiter(RateLimitDecision(allowed=True, remaining=1))
    guard = RateLimitGuard(
        limiter=limiter,
        clock=FrozenClock(datetime(2026, 10, 3, 8, 30)),
    )

    with pytest.raises(RateLimitUnavailable, match="UTC-aware"):
        guard.require(
            RateLimitKey("authentication.login", "alice"),
            RateLimitPolicy(limit=3, window=timedelta(minutes=1)),
        )

    assert limiter.calls == []


@pytest.mark.parametrize("cost", [0, -1, True])
def test_rate_limit_guard_rejects_invalid_cost(cost: object) -> None:
    guard = RateLimitGuard(
        limiter=RecordingLimiter(RateLimitDecision(allowed=True, remaining=1)),
        clock=FrozenClock(),
    )

    with pytest.raises(ValueError, match="cost"):
        guard.require(
            RateLimitKey("authentication.login", "alice"),
            RateLimitPolicy(limit=3, window=timedelta(minutes=1)),
            cost=cost,  # type: ignore[arg-type]
        )
