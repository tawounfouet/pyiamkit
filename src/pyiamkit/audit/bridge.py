"""Bridge domain events into the append-only audit stream."""

from collections.abc import Sequence

from pyiamkit.shared import DomainEvent, DomainEventSink

from .domain import AuditCategory, AuditEvent
from .ports import AuditSink


class DomainEventAuditBridge(DomainEventSink):
    """DomainEventSink adapter that records domain events as audit records."""

    def __init__(self, audit_sink: AuditSink) -> None:
        self._audit = audit_sink

    def publish(self, events: Sequence[DomainEvent]) -> None:
        for event in events:
            self._audit.append(
                AuditEvent(
                    category=AuditCategory.DOMAIN,
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    metadata=event.metadata,
                )
            )
