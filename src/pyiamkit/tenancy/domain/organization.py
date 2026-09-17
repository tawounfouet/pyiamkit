"""Organization entity."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from .errors import InvalidTenant
from .value_objects import OrganizationId, TenantId


@dataclass(frozen=True, slots=True)
class Organization:
    id: OrganizationId
    tenant_id: TenantId
    name: str
    created_at: datetime
    parent_id: OrganizationId | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not 1 <= len(name) <= 255:
            raise InvalidTenant("Organization name must contain between 1 and 255 characters.")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() != timedelta(0):
            raise ValueError("created_at must be UTC-aware")
        if self.parent_id == self.id:
            raise InvalidTenant("Organization cannot be its own parent.")
        object.__setattr__(self, "name", name)
