from datetime import UTC, datetime

import pytest

from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import MembershipNotFound, TenantIsolationGuard, TenantMismatch
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenancyEventSink,
    InMemoryTenantRepository,
)
from pyiamkit.tenancy.application import TenancyApplicationService

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _active_identity(repository: InMemoryIdentityRepository) -> Identity:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    repository.save(identity)
    return identity


def test_membership_in_tenant_a_does_not_grant_tenant_b_context() -> None:
    identity_repository = InMemoryIdentityRepository()
    identity = _active_identity(identity_repository)
    tenant_repository = InMemoryTenantRepository()
    membership_repository = InMemoryMembershipRepository()
    service = TenancyApplicationService(
        tenant_repository=tenant_repository,
        membership_repository=membership_repository,
        identity_repository=identity_repository,
        clock=FrozenClock(),
        event_sink=InMemoryTenancyEventSink(),
    )

    tenant_a = service.activate_tenant(service.create_tenant(name="A", slug="a").id)
    tenant_b = service.activate_tenant(service.create_tenant(name="B", slug="b").id)
    membership = service.create_membership(identity_id=identity.id, tenant_id=tenant_a.id)
    service.activate_membership(membership.id)

    context = service.resolve_context(identity_id=identity.id, tenant_id=tenant_a.id)
    assert context.tenant_id == tenant_a.id

    with pytest.raises(MembershipNotFound):
        service.resolve_context(identity_id=identity.id, tenant_id=tenant_b.id)


def test_tenant_isolation_guard_rejects_mismatch() -> None:
    tenant_repository = InMemoryTenantRepository()
    identity_repository = InMemoryIdentityRepository()
    identity = _active_identity(identity_repository)
    service = TenancyApplicationService(
        tenant_repository=tenant_repository,
        membership_repository=InMemoryMembershipRepository(),
        identity_repository=identity_repository,
        clock=FrozenClock(),
        event_sink=InMemoryTenancyEventSink(),
    )
    tenant_a = service.create_tenant(name="A", slug="a")
    tenant_b = service.create_tenant(name="B", slug="b")

    with pytest.raises(TenantMismatch):
        TenantIsolationGuard.ensure_same_tenant(tenant_a.id, tenant_b.id)

    assert identity.id is not None
