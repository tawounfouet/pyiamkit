"""In-memory Tenancy adapters."""

from collections.abc import Sequence
from datetime import datetime

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent, DomainEventSink

from ..domain.membership import Membership
from ..domain.tenant import Tenant
from ..domain.value_objects import MembershipId, TenantId


class InMemoryTenantRepository:
    def __init__(self) -> None:
        self._items: dict[TenantId, Tenant] = {}

    def get(self, tenant_id: TenantId) -> Tenant | None:
        tenant = self._items.get(tenant_id)
        return None if tenant is None else self._copy(tenant)

    def save(self, tenant: Tenant) -> None:
        self._items[tenant.id] = self._copy(tenant)

    def find_by_slug(self, slug: str) -> Tenant | None:
        normalized = slug.strip().lower()
        for tenant in self._items.values():
            if tenant.slug == normalized:
                return self._copy(tenant)
        return None

    @staticmethod
    def _copy(tenant: Tenant) -> Tenant:
        return Tenant._rehydrate(
            tenant_id=tenant.id,
            version=tenant.version,
            name=tenant.name,
            slug=tenant.slug,
            status=tenant.status,
            created_at=tenant.created_at,
            updated_at=tenant.updated_at,
            metadata=tenant.metadata,
        )


class InMemoryMembershipRepository:
    def __init__(self) -> None:
        self._items: dict[MembershipId, Membership] = {}

    def get(self, membership_id: MembershipId) -> Membership | None:
        membership = self._items.get(membership_id)
        return None if membership is None else self._copy(membership)

    def save(self, membership: Membership) -> None:
        self._items[membership.id] = self._copy(membership)

    def find(self, identity_id: IdentityId, tenant_id: TenantId) -> Membership | None:
        for membership in self._items.values():
            if membership.identity_id == identity_id and membership.tenant_id == tenant_id:
                return self._copy(membership)
        return None

    def find_active(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
        at: datetime,
    ) -> Membership | None:
        membership = self.find(identity_id, tenant_id)
        if membership is None or not membership.is_active(at=at):
            return None
        return membership

    @staticmethod
    def _copy(membership: Membership) -> Membership:
        return Membership._rehydrate(
            membership_id=membership.id,
            version=membership.version,
            identity_id=membership.identity_id,
            tenant_id=membership.tenant_id,
            organization_id=membership.organization_id,
            status=membership.status,
            source=membership.source,
            created_at=membership.created_at,
            updated_at=membership.updated_at,
            valid_from=membership.valid_from,
            valid_until=membership.valid_until,
        )


class InMemoryTenancyEventSink(DomainEventSink):
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def publish(self, events: Sequence[DomainEvent]) -> None:
        self.events.extend(events)
