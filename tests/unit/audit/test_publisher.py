from datetime import UTC, datetime

import pytest

from pyiamkit.audit import OutboxEvent, OutboxEventId, OutboxPublisher, OutboxStatus
from pyiamkit.audit.adapters import InMemoryOutboxRepository
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 2, 17, 30, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


class RecordingPublisher:
    def __init__(self, *, failures: dict[str, int] | None = None) -> None:
        self.calls: list[str] = []
        self._failures = {} if failures is None else dict(failures)

    def publish(self, event: OutboxEvent) -> None:
        self.calls.append(event.event_type)
        remaining = self._failures.get(event.event_type, 0)
        if remaining > 0:
            self._failures[event.event_type] = remaining - 1
            raise RuntimeError(f"publish failed for {event.event_type}")


class FailingMarkPublishedRepository(InMemoryOutboxRepository):
    def __init__(self) -> None:
        super().__init__()
        self.fail_once = True

    def mark_published(self, event_id: OutboxEventId, *, published_at: datetime) -> None:
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("delivery state persistence failed")
        super().mark_published(event_id, published_at=published_at)


def _event(event_type: str = "IdentityDisabled") -> OutboxEvent:
    return OutboxEvent(
        event_type=event_type,
        occurred_at=NOW,
        payload={"reason": "policy"},
    )


def test_outbox_publisher_marks_successful_delivery_published() -> None:
    repository = InMemoryOutboxRepository()
    event = _event()
    repository.append(event)
    transport = RecordingPublisher()

    result = OutboxPublisher(
        repository=repository,
        publisher=transport,
        clock=FrozenClock(),
    ).publish_batch()

    persisted = repository.get(event.id)
    assert persisted is not None
    assert persisted.status is OutboxStatus.PUBLISHED
    assert persisted.published_at == NOW
    assert persisted.attempts == 1
    assert repository.deliverable() == ()
    assert transport.calls == ["IdentityDisabled"]
    assert result.selected == 1
    assert result.attempted == 1
    assert result.published == 1
    assert result.failed == 0
    assert result.failed_event_ids == ()


def test_outbox_publisher_marks_failure_retryable_then_succeeds() -> None:
    repository = InMemoryOutboxRepository()
    event = _event()
    repository.append(event)
    transport = RecordingPublisher(failures={"IdentityDisabled": 1})
    service = OutboxPublisher(
        repository=repository,
        publisher=transport,
        clock=FrozenClock(),
    )

    first = service.publish_batch()

    failed = repository.get(event.id)
    assert failed is not None
    assert failed.status is OutboxStatus.FAILED
    assert failed.published_at is None
    assert failed.attempts == 1
    assert repository.deliverable() == (failed,)
    assert first.failed == 1
    assert first.failed_event_ids == (event.id,)

    second = service.publish_batch()

    published = repository.get(event.id)
    assert published is not None
    assert published.status is OutboxStatus.PUBLISHED
    assert published.published_at == NOW
    assert published.attempts == 2
    assert transport.calls == ["IdentityDisabled", "IdentityDisabled"]
    assert second.published == 1
    assert second.failed == 0


def test_outbox_publisher_continues_after_one_transport_failure() -> None:
    repository = InMemoryOutboxRepository()
    first = _event("First")
    second = _event("Second")
    repository.append(first)
    repository.append(second)
    transport = RecordingPublisher(failures={"First": 1})

    result = OutboxPublisher(
        repository=repository,
        publisher=transport,
        clock=FrozenClock(),
    ).publish_batch()

    persisted_first = repository.get(first.id)
    persisted_second = repository.get(second.id)
    assert persisted_first is not None
    assert persisted_second is not None
    assert persisted_first.status is OutboxStatus.FAILED
    assert persisted_second.status is OutboxStatus.PUBLISHED
    assert result.selected == 2
    assert result.published == 1
    assert result.failed == 1


def test_outbox_publisher_is_at_least_once_when_state_persistence_fails() -> None:
    repository = FailingMarkPublishedRepository()
    event = _event()
    repository.append(event)
    transport = RecordingPublisher()
    service = OutboxPublisher(
        repository=repository,
        publisher=transport,
        clock=FrozenClock(),
    )

    with pytest.raises(RuntimeError, match="state persistence"):
        service.publish_batch()

    still_pending = repository.get(event.id)
    assert still_pending is not None
    assert still_pending.status is OutboxStatus.PENDING

    service.publish_batch()

    persisted = repository.get(event.id)
    assert persisted is not None
    assert persisted.status is OutboxStatus.PUBLISHED
    assert transport.calls == ["IdentityDisabled", "IdentityDisabled"]


@pytest.mark.parametrize("limit", [0, -1, True])
def test_outbox_publisher_validates_limit(limit: object) -> None:
    service = OutboxPublisher(
        repository=InMemoryOutboxRepository(),
        publisher=RecordingPublisher(),
        clock=FrozenClock(),
    )

    with pytest.raises(ValueError, match="limit"):
        service.publish_batch(limit=limit)  # type: ignore[arg-type]
