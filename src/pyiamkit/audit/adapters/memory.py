"""In-memory append-only audit repository."""

from datetime import datetime

from ..domain import AuditEvent, AuditEventId
from ..outbox import OutboxEvent, OutboxEventId, OutboxStatus


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._ids: set[AuditEventId] = set()

    def append(self, event: AuditEvent) -> None:
        if event.id in self._ids:
            raise ValueError(f"Audit event {event.id} already exists")
        self._ids.add(event.id)
        self._events.append(event)

    def all(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def by_correlation_id(self, correlation_id: str) -> tuple[AuditEvent, ...]:
        return tuple(event for event in self._events if event.correlation_id == correlation_id)

    def by_subject(self, subject_id: str) -> tuple[AuditEvent, ...]:
        return tuple(event for event in self._events if event.subject_id == subject_id)


class InMemoryOutboxRepository:
    """Reference outbox repository with explicit delivery-state transitions."""

    def __init__(self) -> None:
        self._events: list[OutboxEvent] = []
        self._by_id: dict[OutboxEventId, OutboxEvent] = {}

    def append(self, event: OutboxEvent) -> None:
        if event.id in self._by_id:
            raise ValueError(f"Outbox event {event.id} already exists")
        self._by_id[event.id] = event
        self._events.append(event)

    def get(self, event_id: OutboxEventId) -> OutboxEvent | None:
        return self._by_id.get(event_id)

    def pending(self, *, limit: int = 100) -> tuple[OutboxEvent, ...]:
        self._validate_limit(limit)
        pending = (event for event in self._events if event.status is OutboxStatus.PENDING)
        return self._ordered(pending, limit=limit)

    def deliverable(self, *, limit: int = 100) -> tuple[OutboxEvent, ...]:
        self._validate_limit(limit)
        events = (event for event in self._events if event.deliverable)
        return self._ordered(events, limit=limit)

    def mark_published(self, event_id: OutboxEventId, *, published_at: datetime) -> None:
        current = self._require(event_id)
        self._replace(current.record_published(published_at=published_at))

    def mark_failed(self, event_id: OutboxEventId) -> None:
        current = self._require(event_id)
        self._replace(current.record_failed())

    def _require(self, event_id: OutboxEventId) -> OutboxEvent:
        event = self._by_id.get(event_id)
        if event is None:
            raise ValueError(f"Outbox event {event_id} does not exist")
        return event

    def _replace(self, event: OutboxEvent) -> None:
        self._by_id[event.id] = event
        for index, existing in enumerate(self._events):
            if existing.id == event.id:
                self._events[index] = event
                return
        raise RuntimeError("Outbox repository index is inconsistent")

    @staticmethod
    def _ordered(events: object, *, limit: int) -> tuple[OutboxEvent, ...]:
        ordered = sorted(
            events,  # type: ignore[arg-type]
            key=lambda event: (event.occurred_at, str(event.id)),
        )
        return tuple(ordered[:limit])

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be an integer >= 1")
