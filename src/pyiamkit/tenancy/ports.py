"""Tenancy persistence ports."""

from datetime import datetime
from typing import Protocol

from pyiamkit.identity import IdentityId

from .domain.membership import Membership
from .domain.tenant import Tenant
from .domain.value_objects import MembershipId, TenantId


class TenantRepository(Protocol):
    def get(self, tenant_id: TenantId) -> Tenant | None: ...
    def save(self, tenant: Tenant) -> None: ...
    def find_by_slug(self, slug: str) -> Tenant | None: ...


class MembershipRepository(Protocol):
    def get(self, membership_id: MembershipId) -> Membership | None: ...
    def save(self, membership: Membership) -> None: ...
    def find(self, identity_id: IdentityId, tenant_id: TenantId) -> Membership | None: ...
    def find_active(
        self, identity_id: IdentityId, tenant_id: TenantId, at: datetime
    ) -> Membership | None: ...
