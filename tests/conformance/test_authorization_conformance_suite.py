from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    AuthorizationDecision,
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
from pyiamkit.conformance import (
    AuthorizationConformance,
    AuthorizationProbe,
    ConformanceFailure,
    TenantIsolationConformance,
    TenantIsolationProbe,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository

NOW = datetime(2026, 10, 3, 9, 15, tzinfo=UTC)
PERMISSION = PermissionCode("invoice.approve")

pytestmark = pytest.mark.conformance


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


@dataclass(slots=True)
class AuthorizationStack:
    engine: AuthorizationEngine
    identity: Identity
    tenant_a: Tenant
    tenant_b: Tenant
    role_a: Role
    bindings: InMemoryRoleBindingRepository

    def request(self, tenant: Tenant) -> AuthorizationRequest:
        return AuthorizationRequest(
            subject_id=self.identity.id,
            tenant_id=tenant.id,
            permission=PERMISSION,
            scope=TenantScope(tenant.id),
            correlation_id="conformance-request",
        )


def _stack(
    *,
    active_identity: bool = True,
    register_permission: bool = True,
    create_tenant_a_binding: bool = True,
) -> AuthorizationStack:
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()

    identity = Identity.create_user(display_name="Conformance User", created_at=NOW)
    identity.pull_events()
    if active_identity:
        identity.activate(at=NOW)
        identity.pull_events()
    identities.save(identity)

    tenant_a = Tenant.create(name="Tenant A", slug="tenant-a", created_at=NOW)
    tenant_a.pull_events()
    tenant_a.activate(at=NOW)
    tenant_a.pull_events()
    tenants.save(tenant_a)

    tenant_b = Tenant.create(name="Tenant B", slug="tenant-b", created_at=NOW)
    tenant_b.pull_events()
    tenant_b.activate(at=NOW)
    tenant_b.pull_events()
    tenants.save(tenant_b)

    for tenant in (tenant_a, tenant_b):
        membership = Membership.create(
            identity_id=identity.id,
            tenant_id=tenant.id,
            created_at=NOW,
        )
        membership.pull_events()
        membership.activate(at=NOW)
        membership.pull_events()
        memberships.save(membership)

    if register_permission:
        permissions.save(Permission(PERMISSION, "Approve invoices"))

    role_a = Role.create(
        name="Approver",
        role_type=RoleType.TENANT,
        tenant_id=tenant_a.id,
        created_at=NOW,
    )
    role_a.pull_events()
    role_a.add_permission(PERMISSION, at=NOW)
    role_a.pull_events()
    roles.save(role_a)

    if create_tenant_a_binding:
        binding = RoleBinding.create(
            identity_id=identity.id,
            role_id=role_a.id,
            tenant_id=tenant_a.id,
            scope=TenantScope(tenant_a.id),
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
    return AuthorizationStack(
        engine=engine,
        identity=identity,
        tenant_a=tenant_a,
        tenant_b=tenant_b,
        role_a=role_a,
        bindings=bindings,
    )


def _allow() -> AuthorizationDecision:
    stack = _stack()
    return stack.engine.authorize(stack.request(stack.tenant_a))


def _no_binding() -> AuthorizationDecision:
    stack = _stack(create_tenant_a_binding=False)
    return stack.engine.authorize(stack.request(stack.tenant_a))


def _unregistered_permission() -> AuthorizationDecision:
    stack = _stack(register_permission=False)
    return stack.engine.authorize(stack.request(stack.tenant_a))


def _inactive_subject() -> AuthorizationDecision:
    stack = _stack(active_identity=False)
    return stack.engine.authorize(stack.request(stack.tenant_a))


def _revoked_access() -> AuthorizationDecision:
    stack = _stack()
    binding = stack.bindings.find_active_for_subject(
        stack.identity.id,
        stack.tenant_a.id,
        NOW,
    )[0]
    binding.revoke(at=NOW)
    binding.pull_events()
    stack.bindings.save(binding)
    return stack.engine.authorize(stack.request(stack.tenant_a))


def _repeat_same_request() -> tuple[AuthorizationDecision, AuthorizationDecision]:
    stack = _stack()
    request = stack.request(stack.tenant_a)
    return stack.engine.authorize(request), stack.engine.authorize(request)


def _cross_tenant_without_binding() -> AuthorizationDecision:
    stack = _stack()
    return stack.engine.authorize(stack.request(stack.tenant_b))


def _foreign_tenant_role() -> AuthorizationDecision:
    stack = _stack()
    foreign_binding = RoleBinding.create(
        identity_id=stack.identity.id,
        role_id=stack.role_a.id,
        tenant_id=stack.tenant_b.id,
        scope=TenantScope(stack.tenant_b.id),
        created_at=NOW,
    )
    foreign_binding.pull_events()
    stack.bindings.save(foreign_binding)
    return stack.engine.authorize(stack.request(stack.tenant_b))


def _construct_scope_mismatch() -> None:
    stack = _stack()
    AuthorizationRequest(
        subject_id=stack.identity.id,
        tenant_id=stack.tenant_a.id,
        permission=PERMISSION,
        scope=TenantScope(stack.tenant_b.id),
    )


def test_authorization_conformance_qualifies_default_engine() -> None:
    report = AuthorizationConformance(
        AuthorizationProbe(
            name="AuthorizationEngine[InMemory]",
            allowed=_allow,
            no_active_binding=_no_binding,
            unregistered_permission=_unregistered_permission,
            inactive_subject=_inactive_subject,
            revoked_access=_revoked_access,
            repeat_same_request=_repeat_same_request,
        )
    ).run()

    report.require_passed()
    assert report.passed is True
    assert report.failures == ()


def test_tenant_isolation_conformance_qualifies_default_engine() -> None:
    report = TenantIsolationConformance(
        TenantIsolationProbe(
            name="AuthorizationEngine[InMemory]",
            same_tenant=_allow,
            cross_tenant_without_binding=_cross_tenant_without_binding,
            foreign_tenant_role=_foreign_tenant_role,
            construct_scope_mismatch=_construct_scope_mismatch,
        )
    ).run()

    report.require_passed()
    assert report.passed is True


def test_tenant_isolation_conformance_detects_cross_tenant_leak() -> None:
    allowed = _allow()
    report = TenantIsolationConformance(
        TenantIsolationProbe(
            name="LeakyAuthorizationAdapter",
            same_tenant=lambda: allowed,
            cross_tenant_without_binding=lambda: allowed,
            foreign_tenant_role=lambda: allowed,
            construct_scope_mismatch=lambda: None,
        )
    ).run()

    assert report.passed is False
    assert {check.name for check in report.failures} == {
        "cross_tenant_binding_does_not_leak",
        "foreign_tenant_role_fails_closed",
        "scope_tenant_mismatch_rejected",
    }
    with pytest.raises(ConformanceFailure, match="LeakyAuthorizationAdapter"):
        report.require_passed()
