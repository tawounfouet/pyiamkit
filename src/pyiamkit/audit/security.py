"""Security-event contracts for downstream SIEM/export pipelines."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from pyiamkit.shared import EntityId


class SecurityEventId(EntityId):
    """Stable identifier for one immutable security event."""


class SecuritySeverity(StrEnum):
    """Portable security-event severity independent from a SIEM vendor."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Immutable security event suitable for durable audit/outbox export."""

    event_type: str
    severity: SecuritySeverity
    occurred_at: datetime
    id: SecurityEventId = field(default_factory=SecurityEventId.new)
    tenant_id: str | None = None
    actor_id: str | None = None
    subject_id: str | None = None
    correlation_id: str | None = None
    payload: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("SecurityEvent.occurred_at must be UTC-aware")

        event_type = self.event_type.strip()
        if not event_type:
            raise ValueError("SecurityEvent.event_type must not be empty")

        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "tenant_id", self._optional_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "actor_id", self._optional_text(self.actor_id, "actor_id"))
        object.__setattr__(self, "subject_id", self._optional_text(self.subject_id, "subject_id"))
        object.__setattr__(
            self,
            "correlation_id",
            self._optional_text(self.correlation_id, "correlation_id"),
        )
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    @staticmethod
    def _optional_text(value: str | None, field_name: str) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"SecurityEvent.{field_name} must not be empty when provided")
        return normalized
