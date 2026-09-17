"""Minimal direct scoped-RBAC authorization example."""

from datetime import UTC, datetime

from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


identities = InMemoryIdentityRepository()
tenants = InMemoryTenantRepository()
memberships = InMemoryMembershipRepository()
permissions = InMemoryPermissionCatalogRepository()
roles = InMemoryRoleRepository()
bindings = InMemoryRoleBindingRepository()

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

membership = Membership.create(identity_id=identity.id, tenant_id=tenant.id, created_at=NOW)
membership.pull_events()
membership.activate(at=NOW)
membership.pull_events()
memberships.save(membership)

permission = Permission(PermissionCode("invoice.approve"), "Approve invoices")
permissions.save(permission)
role = Role.create(name="Approver", role_type=RoleType.TENANT, tenant_id=tenant.id, created_at=NOW)
role.pull_events()
role.add_permission(permission.code, at=NOW)
role.pull_events()
roles.save(role)

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
    clock=FrozenClock(),
)

decision = engine.authorize(
    AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=permission.code,
        scope=TenantScope(tenant.id),
    )
)
print(decision.result.value, decision.reason_code.value)
