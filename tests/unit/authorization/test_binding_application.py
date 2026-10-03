from datetime import UTC, datetime

import pytest

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthenticationEvidence,
    MfaPrivilegedActionGuard,
    PrivilegedActionDenied,
    RoleBindingAlreadyExists,
    RoleBindingApplicationService,
    RoleNotAssignable,
    RoleTenantMismatch,
    RoleType,
)
from pyiamkit.authorization.adapters import InMemoryRoleBindingRepository, InMemoryRoleRepository
from pyiamkit.authorization.domain.role import Role
from pyiamkit.identity import Identity, IdentityId
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantId, TenantMismatch, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _setup(
    *,
    assignable: bool = True,
    mismatched_role_tenant: bool = False,
    sensitive: bool = False,
    privileged_action_guard: MfaPrivilegedActionGuard | None = None,
):
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
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

    role = Role.create(
        name="Manager",
        role_type=RoleType.TENANT,
        tenant_id=TenantId.new() if mismatched_role_tenant else tenant.id,
        assignable=assignable,
        sensitive=sensitive,
        created_at=NOW,
    )
    role.pull_events()
    roles.save(role)

    service = RoleBindingApplicationService(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        role_repository=roles,
        binding_repository=bindings,
        clock=FrozenClock(),
        event_sink=events,
        privileged_action_guard=privileged_action_guard,
    )
    return service, identity, tenant, role, bindings


def test_role_can_be_assigned_with_explicit_tenant_scope() -> None:
    service, identity, tenant, role, _ = _setup()
    binding = service.assign_role(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
    )
    assert binding.identity_id == identity.id
    assert binding.role_id == role.id
    assert service.active_bindings(identity_id=identity.id, tenant_id=tenant.id) == (binding,)


def test_duplicate_active_binding_is_rejected() -> None:
    service, identity, tenant, role, _ = _setup()
    kwargs = {
        "identity_id": identity.id,
        "role_id": role.id,
        "tenant_id": tenant.id,
        "scope": TenantScope(tenant.id),
    }
    service.assign_role(**kwargs)
    with pytest.raises(RoleBindingAlreadyExists):
        service.assign_role(**kwargs)


def test_scope_from_another_tenant_is_rejected() -> None:
    service, identity, tenant, role, _ = _setup()
    with pytest.raises(TenantMismatch):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(TenantId.new()),
        )


def test_role_from_another_tenant_is_rejected() -> None:
    service, identity, tenant, role, _ = _setup(mismatched_role_tenant=True)
    with pytest.raises(RoleTenantMismatch):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
        )


def test_non_assignable_role_is_rejected() -> None:
    service, identity, tenant, role, _ = _setup(assignable=False)
    with pytest.raises(RoleNotAssignable):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
        )


def test_revocation_removes_binding_from_active_set() -> None:
    service, identity, tenant, role, _ = _setup()
    binding = service.assign_role(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
    )
    service.revoke_binding(binding.id)
    assert service.active_bindings(identity_id=identity.id, tenant_id=tenant.id) == ()


def test_sensitive_role_assignment_fails_closed_without_privileged_guard() -> None:
    service, identity, tenant, role, _ = _setup(sensitive=True)

    with pytest.raises(PrivilegedActionDenied, match="explicit privileged-action guard"):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
            granted_by=identity.id,
            authentication=AuthenticationEvidence(
                assurance_level=AssuranceLevel.AAL2,
                mfa=True,
                authenticated_at=NOW,
            ),
        )


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        AuthenticationEvidence(
            assurance_level=AssuranceLevel.AAL2,
            mfa=False,
            authenticated_at=NOW,
        ),
        AuthenticationEvidence(
            assurance_level=AssuranceLevel.AAL1,
            mfa=True,
            authenticated_at=NOW,
        ),
    ],
)
def test_sensitive_role_assignment_requires_actor_mfa_and_aal2(
    evidence: AuthenticationEvidence | None,
) -> None:
    service, identity, tenant, role, _ = _setup(
        sensitive=True,
        privileged_action_guard=MfaPrivilegedActionGuard(),
    )
    admin_actor = IdentityId.new()

    with pytest.raises(PrivilegedActionDenied):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
            granted_by=admin_actor,
            authentication=evidence,
        )


def test_sensitive_role_assignment_accepts_explicit_mfa_aal2_actor() -> None:
    service, identity, tenant, role, _ = _setup(
        sensitive=True,
        privileged_action_guard=MfaPrivilegedActionGuard(),
    )

    admin_actor = IdentityId.new()
    binding = service.assign_role(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        granted_by=admin_actor,
        authentication=AuthenticationEvidence(
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
        ),
    )

    assert binding.role_id == role.id
    assert binding.granted_by == admin_actor


def test_sensitive_role_assignment_rejects_missing_actor_even_with_mfa() -> None:
    service, identity, tenant, role, _ = _setup(
        sensitive=True,
        privileged_action_guard=MfaPrivilegedActionGuard(),
    )

    with pytest.raises(PrivilegedActionDenied, match="explicit actor"):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
            authentication=AuthenticationEvidence(
                assurance_level=AssuranceLevel.AAL2,
                mfa=True,
                authenticated_at=NOW,
            ),
        )


def test_sensitive_role_assignment_rejects_self_assignment_with_reference_guard() -> None:
    service, identity, tenant, role, _ = _setup(
        sensitive=True,
        privileged_action_guard=MfaPrivilegedActionGuard(),
    )

    with pytest.raises(PrivilegedActionDenied, match="self-assignment"):
        service.assign_role(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
            granted_by=identity.id,
            authentication=AuthenticationEvidence(
                assurance_level=AssuranceLevel.AAL2,
                mfa=True,
                authenticated_at=NOW,
            ),
        )
