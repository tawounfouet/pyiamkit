from datetime import UTC, datetime
from decimal import Decimal

import pytest

from pyiamkit.authorization import (
    AccessGovernanceApplicationService,
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    ResourceDescriptor,
    Role,
    RoleBindingApplicationService,
    RoleHierarchyApplicationService,
    RoleType,
    StaticSoDViolation,
)
from pyiamkit.authorization.adapters import (
    InMemoryConstraintRepository,
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
    InMemorySoDRuleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
PERMISSION = PermissionCode("payment.approve")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _runtime_environment():
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    constraints = InMemoryConstraintRepository()
    sod = InMemorySoDRuleRepository()
    events = InMemoryDomainEventSink()

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

    permissions.save(Permission(PERMISSION, "Approve payment"))
    role = Role.create(
        name="Payment Approver",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    role.add_permission(PERMISSION, at=NOW)
    role.pull_events()
    roles.save(role)

    binding_service = RoleBindingApplicationService(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        role_repository=roles,
        binding_repository=bindings,
        clock=FrozenClock(),
        event_sink=events,
    )
    binding_service.assign_role(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
    )

    governance = AccessGovernanceApplicationService(
        permission_repository=permissions,
        role_repository=roles,
        constraint_repository=constraints,
        sod_repository=sod,
        clock=FrozenClock(),
        event_sink=events,
    )
    engine = AuthorizationEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        clock=FrozenClock(),
        constraint_repository=constraints,
        sod_repository=sod,
    )
    return engine, governance, identity, tenant


def _request(identity, tenant, *, attributes):
    return AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=PERMISSION,
        scope=TenantScope(tenant.id),
        resource=ResourceDescriptor("payment", "PAY-001", tenant.id, attributes=attributes),
    )


def test_numeric_maximum_constraint_can_reduce_rbac_allow() -> None:
    engine, governance, identity, tenant = _runtime_environment()
    governance.register_numeric_maximum(
        str(PERMISSION), resource_attribute="amount", maximum=Decimal("100")
    )

    assert engine.authorize(_request(identity, tenant, attributes={"amount": "50"})).allowed
    denied = engine.authorize(_request(identity, tenant, attributes={"amount": "150"}))
    assert denied.reason_code is AuthorizationReason.DENY_CONSTRAINT_VIOLATION
    assert denied.matched_rule_id is not None


def test_missing_constraint_context_fails_closed() -> None:
    engine, governance, identity, tenant = _runtime_environment()
    governance.register_numeric_maximum(
        str(PERMISSION), resource_attribute="amount", maximum=Decimal("100")
    )
    denied = engine.authorize(_request(identity, tenant, attributes={}))
    assert denied.reason_code is AuthorizationReason.DENY_CONSTRAINT_CONTEXT_MISSING


def test_resource_attribute_equals_constraint_is_restrictive() -> None:
    engine, governance, identity, tenant = _runtime_environment()
    governance.register_resource_attribute_equals(
        str(PERMISSION), resource_attribute="status", expected_value="pending"
    )
    denied = engine.authorize(_request(identity, tenant, attributes={"status": "approved"}))
    assert denied.reason_code is AuthorizationReason.DENY_CONSTRAINT_VIOLATION


def test_dynamic_sod_blocks_self_approval() -> None:
    engine, governance, identity, tenant = _runtime_environment()
    governance.register_distinct_actor_sod(
        str(PERMISSION), name="No self approval", resource_attribute="prepared_by"
    )
    denied = engine.authorize(
        _request(identity, tenant, attributes={"prepared_by": str(identity.id)})
    )
    assert denied.reason_code is AuthorizationReason.DENY_SOD_DYNAMIC_CONFLICT

    allowed = engine.authorize(
        _request(identity, tenant, attributes={"prepared_by": "another-user"})
    )
    assert allowed.allowed is True


def test_dynamic_sod_missing_actor_fails_closed() -> None:
    engine, governance, identity, tenant = _runtime_environment()
    governance.register_distinct_actor_sod(
        str(PERMISSION), name="No self approval", resource_attribute="prepared_by"
    )
    denied = engine.authorize(_request(identity, tenant, attributes={}))
    assert denied.reason_code is AuthorizationReason.DENY_SOD_CONTEXT_MISSING


def test_static_sod_blocks_inherited_conflicting_role_assignment() -> None:
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    constraints = InMemoryConstraintRepository()
    sod = InMemorySoDRuleRepository()
    events = InMemoryDomainEventSink()

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

    preparer = Role.create(
        name="Payment Preparer", role_type=RoleType.TENANT, tenant_id=tenant.id, created_at=NOW
    )
    approver = Role.create(
        name="Payment Approver", role_type=RoleType.TENANT, tenant_id=tenant.id, created_at=NOW
    )
    manager = Role.create(
        name="Finance Manager", role_type=RoleType.TENANT, tenant_id=tenant.id, created_at=NOW
    )
    for role in (preparer, approver, manager):
        role.pull_events()
        roles.save(role)
    RoleHierarchyApplicationService(
        role_repository=roles,
        clock=FrozenClock(),
        event_sink=events,
    ).add_parent_role(manager.id, approver.id)

    governance = AccessGovernanceApplicationService(
        permission_repository=permissions,
        role_repository=roles,
        constraint_repository=constraints,
        sod_repository=sod,
        clock=FrozenClock(),
        event_sink=events,
    )
    governance.register_mutually_exclusive_roles(
        name="Maker Checker",
        first_role_id=preparer.id,
        second_role_id=approver.id,
        tenant_id=tenant.id,
    )
    service = RoleBindingApplicationService(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        role_repository=roles,
        binding_repository=bindings,
        clock=FrozenClock(),
        event_sink=events,
        sod_repository=sod,
    )
    service.assign_role(
        identity_id=identity.id,
        role_id=preparer.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
    )
    with pytest.raises(StaticSoDViolation):
        service.assign_role(
            identity_id=identity.id,
            role_id=manager.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
        )
