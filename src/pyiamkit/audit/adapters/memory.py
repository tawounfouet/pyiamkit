"""In-memory append-only audit repository."""

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
    """Reference append-only outbox repository."""

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
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be an integer >= 1")
        pending = (event for event in self._events if event.status is OutboxStatus.PENDING)
        ordered = sorted(pending, key=lambda event: (event.occurred_at, str(event.id)))
        return tuple(ordered[:limit])
