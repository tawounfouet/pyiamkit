from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    AuthorizationDenied,
    AuthorizationEngine,
    AuthorizationReason,
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
from pyiamkit.tenancy import TenantId, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
PERMISSION = PermissionCode("invoice.approve")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _setup(
    *,
    role_has_permission: bool = True,
    register_permission: bool = True,
    create_binding: bool = True,
    disable_role: bool = False,
):
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

    if register_permission:
        permissions.save(Permission(PERMISSION, "Approve invoices"))

    role = Role.create(
        name="Approver",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    if role_has_permission:
        role.add_permission(PERMISSION, at=NOW)
        role.pull_events()
    if disable_role:
        role.disable(at=NOW)
        role.pull_events()
    roles.save(role)

    binding = None
    if create_binding:
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
    request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=PERMISSION,
        scope=TenantScope(tenant.id),
        correlation_id="req-001",
    )
    return engine, request, identity, tenant, membership, role, binding, memberships, bindings


def test_matching_role_binding_allows_request() -> None:
    engine, request, _, _, _, role, binding, _, _ = _setup()
    decision = engine.authorize(request)
    assert decision.allowed is True
    assert decision.reason_code is AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH
    assert decision.matched_role_id == role.id
    assert decision.matched_binding_id == binding.id
    assert decision.correlation_id == "req-001"
    assert decision.explanation_path[-1] == "allow"


def test_default_deny_when_no_active_binding_exists() -> None:
    engine, request, *_ = _setup(create_binding=False)
    decision = engine.authorize(request)
    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING
    assert engine.can(request) is False


def test_permission_must_be_registered() -> None:
    engine, request, *_ = _setup(register_permission=False)
    decision = engine.authorize(request)
    assert decision.reason_code is AuthorizationReason.DENY_PERMISSION_NOT_REGISTERED


def test_role_must_contain_requested_permission() -> None:
    engine, request, *_ = _setup(role_has_permission=False)
    decision = engine.authorize(request)
    assert decision.reason_code is AuthorizationReason.DENY_PERMISSION_NOT_GRANTED


def test_disabled_role_fails_closed() -> None:
    engine, request, *_ = _setup(disable_role=True)
    decision = engine.authorize(request)
    assert decision.reason_code is AuthorizationReason.DENY_ROLE_UNAVAILABLE


def test_revoked_binding_is_not_effective() -> None:
    engine, request, *_, binding, _, bindings = _setup()
    binding.revoke(at=NOW)
    binding.pull_events()
    bindings.save(binding)
    decision = engine.authorize(request)
    assert decision.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING


def test_missing_membership_denies_cross_tenant_request() -> None:
    engine, request, identity, _, _, _, _, _, _ = _setup()
    other_tenant = TenantId.new()
    cross_tenant_request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=other_tenant,
        permission=request.permission,
        scope=TenantScope(other_tenant),
    )
    decision = engine.authorize(cross_tenant_request)
    assert decision.reason_code is AuthorizationReason.DENY_TENANT_NOT_FOUND


def test_scope_mismatch_is_denied_even_with_active_binding() -> None:
    engine, request, identity, tenant, _, role, _, _, bindings = _setup()
    other_scope_tenant = TenantId.new()
    corrupted = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
    )
    corrupted.pull_events()
    bindings.save(corrupted)
    mismatched_request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=request.permission,
        scope=TenantScope(tenant.id),
    )
    assert engine.authorize(mismatched_request).allowed is True
    with pytest.raises(ValueError):
        AuthorizationRequest(
            subject_id=identity.id,
            tenant_id=tenant.id,
            permission=request.permission,
            scope=TenantScope(other_scope_tenant),
        )


def test_require_raises_structured_denial() -> None:
    engine, request, *_ = _setup(role_has_permission=False)
    with pytest.raises(AuthorizationDenied) as exc_info:
        engine.require(request)
    assert exc_info.value.decision.reason_code is AuthorizationReason.DENY_PERMISSION_NOT_GRANTED


def test_require_and_explain_return_allow_decision() -> None:
    engine, request, *_ = _setup()
    required = engine.require(request)
    explained = engine.explain(request)
    assert required.allowed is True
    assert explained.allowed is True
    assert explained.reason_code is AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH
