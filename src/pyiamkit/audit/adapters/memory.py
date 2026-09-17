"""In-memory append-only audit repository."""

from ..domain import AuditEvent, AuditEventId


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
