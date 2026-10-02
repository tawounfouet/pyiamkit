"""Public append-only audit API."""

from .bridge import DomainEventAuditBridge
from .domain import AuditCategory, AuditEvent, AuditEventId, AuditOutcome
from .ports import AuditRepository, AuditSink
from .security import SecurityEvent, SecurityEventId, SecuritySeverity

__all__ = [
    "AuditCategory",
    "AuditEvent",
    "AuditEventId",
    "AuditOutcome",
    "AuditRepository",
    "AuditSink",
    "DomainEventAuditBridge",
    "SecurityEvent",
    "SecurityEventId",
    "SecuritySeverity",
]
