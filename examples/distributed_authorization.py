"""Distributed authorization with authoritative state and mutation-driven invalidation."""

from datetime import UTC, datetime

from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationRequest,
    PermissionCode,
    RoleBinding,
    RoleCatalogApplicationService,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.operations import (
    DistributedAuthorizationRuntime,
    SecurityStateMutationEventSink,
)
from pyiamkit.operations.adapters import (
    InMemoryAuthorizationCache,
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


clock = FrozenClock()
identities = InMemoryIdentityRepository()
tenants = InMemoryTenantRepository()
memberships = InMemoryMembershipRepository()
permissions = InMemoryPermissionCatalogRepository()
roles = InMemoryRoleRepository()
bindings = InMemoryRoleBindingRepository()

state = InMemorySecurityStateStore()
cache = InMemoryAuthorizationCache()
revocations = InMemoryRevocationRegistry()
domain_events = InMemoryDomainEventSink()
security_events = SecurityStateMutationEventSink(
    domain_events,
    state_writer=state,
    revocations=revocations,
)

identity = Identity.create_user(display_name="Alice", created_at=NOW)
identity.pull_events()
identity.activate(at=NOW)
identity.pull_events()
identities.save(identity)

tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
tenant.pull_events()
tenant.activate(at=NOW)
tenant.pull_events()
tenants.save(tenant)

membership = Membership.create(
    identity_id=identity.id,
    tenant_id=tenant.id,
    created_at=NOW,
)
membership.pull_events()
membership.activate(at=NOW)
membership.pull_events()
memberships.save(membership)

catalog = RoleCatalogApplicationService(
    role_repository=roles,
    permission_repository=permissions,
    clock=clock,
    event_sink=security_events,
)
permission = catalog.register_permission("invoice.read", description="Read invoices")
role = catalog.create_role(
    name="Reader",
    role_type=RoleType.TENANT,
    tenant_id=tenant.id,
)
catalog.add_permission(role.id, permission.code.value)

binding = RoleBinding.create(
    identity_id=identity.id,
    role_id=role.id,
    tenant_id=tenant.id,
    scope=TenantScope(tenant.id),
    created_at=NOW,
)
binding.pull_events()
bindings.save(binding)

engine = AuthorizationEngine(
    identity_repository=identities,
    tenant_repository=tenants,
    membership_repository=memberships,
    permission_repository=permissions,
    role_repository=roles,
    binding_repository=bindings,
    clock=clock,
)
runtime = DistributedAuthorizationRuntime(
    engine=engine,
    security_state=state,
    cache=cache,
    revocations=revocations,
    clock=clock,
)
request = AuthorizationRequest(
    subject_id=identity.id,
    tenant_id=tenant.id,
    permission=PermissionCode("invoice.read"),
    scope=TenantScope(tenant.id),
)

first = runtime.authorize(request)
second = runtime.authorize(request)
assert first.allowed is True
assert second.allowed is True

catalog.remove_permission(role.id, "invoice.read")

after_mutation = runtime.authorize(request)
assert after_mutation.allowed is False

print(first.result.value, "→ cached", second.result.value, "→ mutation", after_mutation.result.value)
