from datetime import UTC, datetime

from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleHierarchyApplicationService,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
PERMISSION = PermissionCode("invoice.approve")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def test_engine_allows_permission_inherited_from_global_parent() -> None:
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

    permissions.save(Permission(PERMISSION, "Approve invoices"))
    parent = Role.create(name="Base Approver", role_type=RoleType.SYSTEM, created_at=NOW)
    parent.pull_events()
    parent.add_permission(PERMISSION, at=NOW)
    parent.pull_events()
    roles.save(parent)

    child = Role.create(
        name="Tenant Finance Manager",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    child.pull_events()
    roles.save(child)
    RoleHierarchyApplicationService(
        role_repository=roles,
        clock=FrozenClock(),
        event_sink=InMemoryDomainEventSink(),
    ).add_parent_role(child.id, parent.id)

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=child.id,
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
            permission=PERMISSION,
            scope=TenantScope(tenant.id),
        )
    )

    assert decision.allowed is True
    assert decision.reason_code is AuthorizationReason.ALLOW_INHERITED_ROLE_PERMISSION_MATCH
    assert decision.bound_role_id == child.id
    assert decision.matched_role_id == parent.id
    assert decision.matched_binding_id == binding.id
    assert f"role:{child.id}" in decision.explanation_path
    assert f"role:{parent.id}" in decision.explanation_path
