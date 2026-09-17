"""Tenancy value objects."""

from dataclasses import dataclass
from enum import StrEnum

from pyiamkit.identity import IdentityId
from pyiamkit.shared import EntityId


class TenantId(EntityId):
    """Stable opaque identifier for a Tenant aggregate."""


class MembershipId(EntityId):
    """Stable opaque identifier for a Membership aggregate."""


class OrganizationId(EntityId):
    """Stable opaque identifier for an Organization."""


class TenantStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class MembershipStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class TenantScope:
    tenant_id: TenantId

    def contains(self, other: "TenantScope") -> bool:
        return self.tenant_id == other.tenant_id


@dataclass(frozen=True, slots=True)
class TenantContext:
    identity_id: IdentityId
    tenant_id: TenantId
    membership_id: MembershipId
    organization_id: OrganizationId | None = None
