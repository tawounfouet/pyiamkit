"""Public append-only audit API."""

from .bridge import DomainEventAuditBridge
from .domain import AuditCategory, AuditEvent, AuditEventId, AuditOutcome
from .outbox import OutboxEvent, OutboxEventId, OutboxStatus
from .ports import AuditOutboxWriter, AuditRepository, AuditSink, OutboxRepository
from .security import SecurityEvent, SecurityEventId, SecuritySeverity

__all__ = [
    "AuditCategory",
    "AuditEvent",
    "AuditEventId",
    "AuditOutcome",
    "AuditOutboxWriter",
    "AuditRepository",
    "AuditSink",
    "DomainEventAuditBridge",
    "OutboxEvent",
    "OutboxEventId",
    "OutboxRepository",
    "OutboxStatus",
    "SecurityEvent",
    "SecurityEventId",
    "SecuritySeverity",
]
