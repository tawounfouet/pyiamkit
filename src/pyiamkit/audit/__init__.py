"""Public append-only audit API."""

from .bridge import DomainEventAuditBridge
from .domain import AuditCategory, AuditEvent, AuditEventId, AuditOutcome
from .outbox import OutboxEvent, OutboxEventId, OutboxStatus
from .ports import (
    AuditOutboxWriter,
    AuditRepository,
    AuditSink,
    EventPublisher,
    OutboxRepository,
)
from .publisher import OutboxPublishBatchResult, OutboxPublisher
from .security import SecurityEvent, SecurityEventId, SecuritySeverity

__all__ = [
    "AuditCategory",
    "AuditEvent",
    "AuditEventId",
    "AuditOutboxWriter",
    "AuditOutcome",
    "AuditRepository",
    "AuditSink",
    "DomainEventAuditBridge",
    "EventPublisher",
    "OutboxEvent",
    "OutboxEventId",
    "OutboxPublishBatchResult",
    "OutboxPublisher",
    "OutboxRepository",
    "OutboxStatus",
    "SecurityEvent",
    "SecurityEventId",
    "SecuritySeverity",
]
