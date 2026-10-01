"""Invalidation value types for distributed IAM operations."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from pyiamkit.tenancy import TenantId

from .state import StateVersion


class InvalidationKind(StrEnum):
    """Security-state dimensions that can invalidate derived runtime state."""

    IDENTITY = "identity"
    TENANT = "tenant"
    MEMBERSHIP = "membership"
    AUTHORIZATION = "authorization"
    GOVERNANCE = "governance"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True)
class InvalidationEvent:
    """Low-latency signal that authoritative security state has advanced."""

    kind: InvalidationKind
    target_id: str
    state_version: StateVersion
    occurred_at: datetime
    tenant_id: TenantId | None = None
    event_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, InvalidationKind):
            raise TypeError("InvalidationEvent.kind must be an InvalidationKind")
        if not isinstance(self.target_id, str):
            raise TypeError("InvalidationEvent.target_id must be a string")
        target_id = self.target_id.strip()
        if not target_id:
            raise ValueError("InvalidationEvent.target_id must not be empty")
        if not isinstance(self.state_version, StateVersion):
            raise TypeError("InvalidationEvent.state_version must be a StateVersion")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("InvalidationEvent.occurred_at must be UTC-aware")
        if self.tenant_id is not None and not isinstance(self.tenant_id, TenantId):
            raise TypeError("InvalidationEvent.tenant_id must be a TenantId")
        if not isinstance(self.event_id, UUID):
            raise TypeError("InvalidationEvent.event_id must be a UUID")
        object.__setattr__(self, "target_id", target_id)
