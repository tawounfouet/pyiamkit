"""Minimal multi-tenant context example."""

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import SystemClock
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenancyEventSink,
    InMemoryTenantRepository,
)

identity_repository = InMemoryIdentityRepository()
identity_service = IdentityApplicationService(
    repository=identity_repository,
    clock=SystemClock(),
    event_sink=InMemoryDomainEventSink(),
)
alice = identity_service.create_user(display_name="Alice", primary_email="alice@example.com")
alice = identity_service.activate_identity(alice.id)

tenancy = TenancyApplicationService(
    tenant_repository=InMemoryTenantRepository(),
    membership_repository=InMemoryMembershipRepository(),
    identity_repository=identity_repository,
    clock=SystemClock(),
    event_sink=InMemoryTenancyEventSink(),
)
acme = tenancy.create_tenant(name="ACME", slug="acme")
acme = tenancy.activate_tenant(acme.id)
membership = tenancy.create_membership(identity_id=alice.id, tenant_id=acme.id)
tenancy.activate_membership(membership.id)

context = tenancy.resolve_context(identity_id=alice.id, tenant_id=acme.id)
print(f"Resolved tenant context: {context.tenant_id}")
