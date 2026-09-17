"""RoleBinding value objects."""

from enum import StrEnum

from pyiamkit.shared import EntityId


class RoleBindingId(EntityId):
    """Stable opaque identifier for a RoleBinding aggregate."""


class RoleBindingStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class GrantSource(StrEnum):
    DIRECT = "direct"
    SYSTEM = "system"
    MIGRATION = "migration"
