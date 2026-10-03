import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pyiamkit.authorization import (
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
from pyiamkit.tenancy import Membership, Tenant, TenantId, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository

NOW = datetime(2026, 10, 3, 8, 30, tzinfo=UTC)
_SEGMENT = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10)


class MutableClock(Clock):
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


@dataclass(slots=True)
class AuthorizationFixture:
    engine: AuthorizationEngine
    request: AuthorizationRequest
    identity: Identity
    tenant: Tenant
    membership: Membership
    role: Role
    binding: RoleBinding
    identities: InMemoryIdentityRepository
    tenants: InMemoryTenantRepository
    memberships: InMemoryMembershipRepository
    bindings: InMemoryRoleBindingRepository
    clock: MutableClock


def _build_fixture(
    permission: PermissionCode,
    *,
    membership_valid_until: datetime | None = None,
    binding_valid_until: datetime | None = None,
) -> AuthorizationFixture:
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    clock = MutableClock(NOW)

    identity = Identity.create_user(display_name="Property Subject", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identities.save(identity)

    tenant = Tenant.create(name="Property Tenant", slug="property-tenant", created_at=NOW)
    tenant.pull_events()
    tenant.activate(at=NOW)
    tenant.pull_events()
    tenants.save(tenant)

    membership = Membership.create(
        identity_id=identity.id,
        tenant_id=tenant.id,
        created_at=NOW,
        valid_until=membership_valid_until,
    )
    membership.pull_events()
    membership.activate(at=NOW)
    membership.pull_events()
    memberships.save(membership)

    permissions.save(Permission(permission, "Property-generated permission"))

    role = Role.create(
        name="Property Role",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    role.add_permission(permission, at=NOW)
    role.pull_events()
    roles.save(role)

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
        valid_until=binding_valid_until,
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
    request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=permission,
        scope=TenantScope(tenant.id),
    )
    return AuthorizationFixture(
        engine=engine,
        request=request,
        identity=identity,
        tenant=tenant,
        membership=membership,
        role=role,
        binding=binding,
        identities=identities,
        tenants=tenants,
        memberships=memberships,
        bindings=bindings,
        clock=clock,
    )


@settings(max_examples=40, deadline=None)
@given(resource=_SEGMENT, action=_SEGMENT)
@pytest.mark.security
def test_property_cross_tenant_binding_never_authorizes_other_tenant(
    resource: str,
    action: str,
) -> None:
    permission = PermissionCode(f"{resource}.{action}")
    fixture = _build_fixture(permission)

    other_tenant = Tenant.create(name="Other Tenant", slug="other-tenant", created_at=NOW)
    other_tenant.pull_events()
    other_tenant.activate(at=NOW)
    other_tenant.pull_events()
    fixture.tenants.save(other_tenant)

    other_membership = Membership.create(
        identity_id=fixture.identity.id,
        tenant_id=other_tenant.id,
        created_at=NOW,
    )
    other_membership.pull_events()
    other_membership.activate(at=NOW)
    other_membership.pull_events()
    fixture.memberships.save(other_membership)

    request = AuthorizationRequest(
        subject_id=fixture.identity.id,
        tenant_id=other_tenant.id,
        permission=permission,
        scope=TenantScope(other_tenant.id),
    )

    decision = fixture.engine.authorize(request)

    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING


@settings(max_examples=40, deadline=None)
@given(resource=_SEGMENT, action=_SEGMENT)
@pytest.mark.security
def test_property_revocation_never_increases_access(resource: str, action: str) -> None:
    permission = PermissionCode(f"{resource}.{action}")
    fixture = _build_fixture(permission)

    assert fixture.engine.authorize(fixture.request).allowed is True

    fixture.binding.revoke(at=NOW)
    fixture.binding.pull_events()
    fixture.bindings.save(fixture.binding)

    decision = fixture.engine.authorize(fixture.request)

    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING


@settings(max_examples=40, deadline=None)
@given(resource=_SEGMENT, action=_SEGMENT)
@pytest.mark.security
def test_property_disabled_subject_never_authorizes(resource: str, action: str) -> None:
    permission = PermissionCode(f"{resource}.{action}")
    fixture = _build_fixture(permission)

    assert fixture.engine.authorize(fixture.request).allowed is True

    fixture.identity.disable(at=NOW, reason="property-security-test")
    fixture.identity.pull_events()
    fixture.identities.save(fixture.identity)

    decision = fixture.engine.authorize(fixture.request)

    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_SUBJECT_INACTIVE


@settings(max_examples=40, deadline=None)
@given(
    resource=_SEGMENT,
    action=_SEGMENT,
    lifetime_seconds=st.integers(min_value=1, max_value=86_400),
    expire_membership=st.booleans(),
)
@pytest.mark.security
def test_property_expired_access_never_authorizes(
    resource: str,
    action: str,
    lifetime_seconds: int,
    expire_membership: bool,
) -> None:
    permission = PermissionCode(f"{resource}.{action}")
    valid_until = NOW + timedelta(seconds=lifetime_seconds)
    fixture = _build_fixture(
        permission,
        membership_valid_until=valid_until if expire_membership else None,
        binding_valid_until=None if expire_membership else valid_until,
    )

    assert fixture.engine.authorize(fixture.request).allowed is True

    fixture.clock.value = valid_until + timedelta(microseconds=1)
    decision = fixture.engine.authorize(fixture.request)

    assert decision.allowed is False
    assert decision.reason_code in {
        AuthorizationReason.DENY_MEMBERSHIP_NOT_FOUND,
        AuthorizationReason.DENY_NO_ACTIVE_BINDING,
    }


@settings(max_examples=40, deadline=None)
@given(resource=_SEGMENT, action=_SEGMENT)
@pytest.mark.security
def test_property_scope_mismatch_is_rejected_before_authorization(
    resource: str,
    action: str,
) -> None:
    permission = PermissionCode(f"{resource}.{action}")
    subject_fixture = _build_fixture(permission)
    other_tenant_id = TenantId.new()

    with pytest.raises(ValueError):
        AuthorizationRequest(
            subject_id=subject_fixture.identity.id,
            tenant_id=subject_fixture.tenant.id,
            permission=permission,
            scope=TenantScope(other_tenant_id),
        )
