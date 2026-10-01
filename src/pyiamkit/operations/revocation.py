"""Revocation value types for distributed IAM operations."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from pyiamkit.tenancy import TenantId

from .state import StateVersion


class RevocationTargetType(StrEnum):
    """Security-sensitive target categories that can be revoked."""

    SESSION = "session"
    IDENTITY = "identity"
    MEMBERSHIP = "membership"
    ROLE_BINDING = "role_binding"
    TENANT = "tenant"


_REACTIVABLE_TARGETS = frozenset(
    {
        RevocationTargetType.IDENTITY,
        RevocationTargetType.MEMBERSHIP,
        RevocationTargetType.TENANT,
    }
)


@dataclass(frozen=True, slots=True)
class RevocationMarker:
    """Immutable deny-fast marker projected from authoritative security state."""

    target_type: RevocationTargetType
    target_id: str
    revoked_at: datetime
    reason_code: str
    tenant_id: TenantId | None = None
    expires_at: datetime | None = None
    source_version: StateVersion | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target_type, RevocationTargetType):
            raise TypeError("RevocationMarker.target_type must be a RevocationTargetType")
        target_id = self.target_id.strip()
        reason_code = self.reason_code.strip()
        if not target_id:
            raise ValueError("RevocationMarker.target_id must not be empty")
        if not reason_code:
            raise ValueError("RevocationMarker.reason_code must not be empty")
        _require_utc(self.revoked_at, field_name="revoked_at")
        if self.expires_at is not None:
            _require_utc(self.expires_at, field_name="expires_at")
            if self.expires_at <= self.revoked_at:
                raise ValueError("RevocationMarker.expires_at must be after revoked_at")
        if self.tenant_id is not None and not isinstance(self.tenant_id, TenantId):
            raise TypeError("RevocationMarker.tenant_id must be a TenantId")
        if self.source_version is not None and not isinstance(self.source_version, StateVersion):
            raise TypeError("RevocationMarker.source_version must be a StateVersion")
        if self.target_type in _REACTIVABLE_TARGETS and self.source_version is None:
            raise ValueError(
                "RevocationMarker.source_version is required for reactivable targets"
            )
        object.__setattr__(self, "target_id", target_id)
        object.__setattr__(self, "reason_code", reason_code)

    def is_active(self, *, at: datetime) -> bool:
        """Return whether this marker temporally revokes the target at the given time."""

        _require_utc(at, field_name="at")
        return self.revoked_at <= at and (self.expires_at is None or at < self.expires_at)

    def applies_to(self, current_version: StateVersion) -> bool:
        """Return whether this marker is not stale against current authoritative state."""

        if not isinstance(current_version, StateVersion):
            raise TypeError("current_version must be a StateVersion")
        return self.source_version is None or self.source_version >= current_version


def _require_utc(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC-aware")
