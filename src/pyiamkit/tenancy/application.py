"""Tenancy application orchestration."""

from datetime import datetime

from pyiamkit.identity import IdentityId, IdentityRepository, IdentityStatus
from pyiamkit.shared import Clock, DomainEventSink

from .domain.errors import MembershipInactive, MembershipNotFound, TenantInactive, TenantNotFound
from .domain.membership import Membership
from .domain.tenant import Tenant
from .domain.value_objects import OrganizationId, TenantContext, TenantId, TenantStatus
from .ports import MembershipRepository, TenantRepository


class TenancyApplicationService:
    def __init__(self, *, tenant_repository: TenantRepository,
                 membership_repository: MembershipRepository,
                 identity_repository: IdentityRepository, clock: Clock,
                 event_sink: DomainEventSink) -> None:
        self._tenants = tenant_repository
        self._memberships = membership_repository
        self._identities = identity_repository
        self._clock = clock
        self._events = event_sink

    def create_tenant(self, *, name: str, slug: str) -> Tenant:
        if self._tenants.find_by_slug(slug) is not None:
            from .domain.errors import InvalidTenant
            raise InvalidTenant(f"Tenant slug {slug!r} already exists.")
        tenant = Tenant.create(name=name, slug=slug, created_at=self._clock.now())
        return self._save_tenant(tenant)

    def activate_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._require_tenant(tenant_id)
        tenant.activate(at=self._clock.now())
        return self._save_tenant(tenant)

    def suspend_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._require_tenant(tenant_id)
        tenant.suspend(at=self._clock.now())
        return self._save_tenant(tenant)

    def reactivate_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._require_tenant(tenant_id)
        tenant.reactivate(at=self._clock.now())
        return self._save_tenant(tenant)

    def disable_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._require_tenant(tenant_id)
        tenant.disable(at=self._clock.now())
        return self._save_tenant(tenant)

    def archive_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._require_tenant(tenant_id)
        tenant.archive(at=self._clock.now())
        return self._save_tenant(tenant)

    def create_membership(self, *, identity_id: IdentityId, tenant_id: TenantId,
                          organization_id: OrganizationId | None = None,
                          valid_until: datetime | None = None,
                          source: str = "direct") -> Membership:
        if self._identities.get(identity_id) is None:
            from pyiamkit.identity import IdentityNotFound
            raise IdentityNotFound(identity_id)
        self._require_tenant(tenant_id)
        existing = self._memberships.find(identity_id, tenant_id)
        if existing is not None:
            from .domain.errors import InvalidMembership
            raise InvalidMembership("Identity already has a membership in this tenant.")
        membership = Membership.create(identity_id=identity_id, tenant_id=tenant_id,
            organization_id=organization_id, created_at=self._clock.now(),
            valid_until=valid_until, source=source)
        return self._save_membership(membership)

    def activate_membership(self, membership_id: object) -> Membership:
        membership = self._require_membership_id(membership_id)
        identity = self._identities.get(membership.identity_id)
        if identity is None or identity.status is not IdentityStatus.ACTIVE:
            raise MembershipInactive("Membership requires an active identity.")
        tenant = self._require_tenant(membership.tenant_id)
        if tenant.status is not TenantStatus.ACTIVE:
            raise TenantInactive("Membership requires an active tenant.")
        membership.activate(at=self._clock.now())
        return self._save_membership(membership)

    def resolve_context(self, *, identity_id: IdentityId, tenant_id: TenantId) -> TenantContext:
        identity = self._identities.get(identity_id)
        if identity is None or identity.status is not IdentityStatus.ACTIVE:
            raise MembershipInactive("Active identity required for tenant context.")
        tenant = self._require_tenant(tenant_id)
        if tenant.status is not TenantStatus.ACTIVE:
            raise TenantInactive("Active tenant required for tenant context.")
        membership = self._memberships.find_active(identity_id, tenant_id, self._clock.now())
        if membership is None:
            raise MembershipNotFound(identity_id, tenant_id)
        return TenantContext(identity_id=identity_id, tenant_id=tenant_id,
            membership_id=membership.id, organization_id=membership.organization_id)

    def _require_tenant(self, tenant_id: TenantId) -> Tenant:
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            raise TenantNotFound(tenant_id)
        return tenant

    def _require_membership_id(self, membership_id: object) -> Membership:
        from .domain.value_objects import MembershipId
        if not isinstance(membership_id, MembershipId):
            raise MembershipNotFound("unknown", "unknown")
        membership = self._memberships.get(membership_id)
        if membership is None:
            raise MembershipNotFound("unknown", "unknown")
        return membership

    def _save_tenant(self, tenant: Tenant) -> Tenant:
        events = tenant.pull_events()
        self._tenants.save(tenant)
        self._events.publish(events)
        saved = self._tenants.get(tenant.id)
        assert saved is not None
        return saved

    def _save_membership(self, membership: Membership) -> Membership:
        events = membership.pull_events()
        self._memberships.save(membership)
        self._events.publish(events)
        saved = self._memberships.get(membership.id)
        assert saved is not None
        return saved
