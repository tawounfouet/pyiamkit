from datetime import UTC, datetime, timedelta
from types import MappingProxyType

import pytest

from pyiamkit.audit import OutboxEvent, OutboxEventId, OutboxStatus
from pyiamkit.audit.adapters import InMemoryOutboxRepository

NOW = datetime(2026, 10, 2, 14, 30, tzinfo=UTC)


def _event(
    *,
    event_type: str = "IdentityDisabled",
    occurred_at: datetime = NOW,
    status: OutboxStatus = OutboxStatus.PENDING,
    published_at: datetime | None = None,
) -> OutboxEvent:
    return OutboxEvent(
        event_type=event_type,
        event_version=1,
        aggregate_type="Identity",
        aggregate_id="identity-1",
        aggregate_version=4,
        tenant_id="tenant-1",
        payload={"reason": "policy"},
        occurred_at=occurred_at,
        status=status,
        published_at=published_at,
    )


def test_outbox_event_is_immutable_and_normalizes_context() -> None:
    payload: dict[str, object] = {"reason": "policy"}
    event = OutboxEvent(
        event_type="  IdentityDisabled  ",
        aggregate_type=" Identity ",
        aggregate_id=" identity-1 ",
        tenant_id=" tenant-1 ",
        payload=payload,
        occurred_at=NOW,
    )

    payload["reason"] = "changed"

    assert isinstance(event.id, OutboxEventId)
    assert event.event_type == "IdentityDisabled"
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "identity-1"
    assert event.tenant_id == "tenant-1"
    assert event.payload == {"reason": "policy"}
    assert isinstance(event.payload, MappingProxyType)

    with pytest.raises(TypeError):
        event.payload["reason"] = "tampered"  # type: ignore[index]


@pytest.mark.parametrize("value", [0, -1, True, "1"])
def test_outbox_event_rejects_invalid_event_version(value: object) -> None:
    with pytest.raises(ValueError, match="event_version"):
        OutboxEvent(
            event_type="IdentityDisabled",
            event_version=value,  # type: ignore[arg-type]
            payload={},
            occurred_at=NOW,
        )


@pytest.mark.parametrize("value", [-1, True, "1"])
def test_outbox_event_rejects_invalid_attempts(value: object) -> None:
    with pytest.raises(ValueError, match="attempts"):
        OutboxEvent(
            event_type="IdentityDisabled",
            attempts=value,  # type: ignore[arg-type]
            payload={},
            occurred_at=NOW,
        )


def test_outbox_event_requires_consistent_publish_state() -> None:
    with pytest.raises(ValueError, match="requires published_at"):
        _event(status=OutboxStatus.PUBLISHED)

    with pytest.raises(ValueError, match="Only published"):
        _event(published_at=NOW)


def test_outbox_event_requires_utc_timestamps() -> None:
    with pytest.raises(ValueError, match="occurred_at"):
        _event(occurred_at=NOW.replace(tzinfo=None))

    with pytest.raises(ValueError, match="published_at"):
        _event(
            status=OutboxStatus.PUBLISHED,
            published_at=NOW.replace(tzinfo=None),
        )


def test_in_memory_outbox_repository_is_append_only_and_orders_pending() -> None:
    repository = InMemoryOutboxRepository()
    later = _event(event_type="Later", occurred_at=NOW + timedelta(seconds=2))
    first = _event(event_type="First", occurred_at=NOW)
    published = _event(
        event_type="Published",
        occurred_at=NOW + timedelta(seconds=1),
        status=OutboxStatus.PUBLISHED,
        published_at=NOW + timedelta(seconds=3),
    )

    repository.append(later)
    repository.append(first)
    repository.append(published)

    assert repository.get(first.id) == first
    assert repository.pending() == (first, later)
    assert repository.pending(limit=1) == (first,)

    with pytest.raises(ValueError, match="already exists"):
        repository.append(first)


@pytest.mark.parametrize("limit", [0, -1, True])
def test_in_memory_outbox_repository_validates_pending_limit(limit: object) -> None:
    repository = InMemoryOutboxRepository()

    with pytest.raises(ValueError, match="limit"):
        repository.pending(limit=limit)  # type: ignore[arg-type]
