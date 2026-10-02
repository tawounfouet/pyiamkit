"""Audit persistence and delivery ports."""

from typing import Protocol

from .domain import AuditEvent
from .outbox import OutboxEvent, OutboxEventId


class AuditSink(Protocol):
    """Append one immutable audit record."""

    def append(self, event: AuditEvent) -> None: ...


class AuditRepository(AuditSink, Protocol):
    """Append-only audit store with query capabilities."""

    def all(self) -> tuple[AuditEvent, ...]: ...
    def by_correlation_id(self, correlation_id: str) -> tuple[AuditEvent, ...]: ...
    def by_subject(self, subject_id: str) -> tuple[AuditEvent, ...]: ...



class OutboxRepository(Protocol):
    """Durable append-only publication intents."""

    def append(self, event: OutboxEvent) -> None: ...
    def get(self, event_id: OutboxEventId) -> OutboxEvent | None: ...
    def pending(self, *, limit: int = 100) -> tuple[OutboxEvent, ...]: ...


class AuditOutboxWriter(Protocol):
    """Atomically append required audit evidence and publication intent."""

    def append(self, audit_event: AuditEvent, outbox_event: OutboxEvent) -> None: ...
