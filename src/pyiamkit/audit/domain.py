"""Audit domain objects."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from pyiamkit.shared import EntityId


class AuditEventId(EntityId):
    """Stable identifier for one immutable audit record."""


class AuditCategory(StrEnum):
    AUTHORIZATION = "authorization"
    DOMAIN = "domain"


class AuditOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Append-only security/audit record with intentionally minimal payload."""

    category: AuditCategory
    event_type: str
    occurred_at: datetime
    id: AuditEventId = field(default_factory=AuditEventId.new)
    actor_id: str | None = None
    subject_id: str | None = None
    tenant_id: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: AuditOutcome | None = None
    reason_code: str | None = None
    correlation_id: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("AuditEvent.occurred_at must be UTC-aware")
        event_type = self.event_type.strip()
        if not event_type:
            raise ValueError("AuditEvent.event_type must not be empty")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
