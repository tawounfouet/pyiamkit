"""Authorization catalog value objects."""

import re
from dataclasses import dataclass
from enum import StrEnum

from pyiamkit.shared import EntityId

from .errors import InvalidPermissionCode

_PERMISSION_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


class RoleId(EntityId):
    """Stable opaque identifier for a Role aggregate."""


class RoleStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class RoleType(StrEnum):
    SYSTEM = "system"
    TENANT = "tenant"
    BUSINESS = "business"
    TECHNICAL = "technical"


@dataclass(frozen=True, slots=True, order=True)
class PermissionCode:
    """Canonical stable permission identifier such as ``invoice.approve``."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().lower()
        if not _PERMISSION_PATTERN.fullmatch(normalized):
            raise InvalidPermissionCode(self.value)
        object.__setattr__(self, "value", normalized)

    @property
    def action(self) -> str:
        return self.value.rsplit(".", 1)[1]

    @property
    def resource(self) -> str:
        return self.value.rsplit(".", 1)[0]

    def __str__(self) -> str:
        return self.value
