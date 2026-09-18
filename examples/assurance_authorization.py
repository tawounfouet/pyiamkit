from datetime import UTC, datetime

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthenticationEvidence,
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    GovernanceRuleId,
    MinimumAssuranceConstraint,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryConstraintRepository,
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)

identities = InMemoryIdentityRepository()
tenants = InMemoryTenantRepository()
memberships = InMemoryMembershipRepository()
permissions = InMemoryPermissionCatalogRepository()
roles = InMemoryRoleRepository()
bindings = InMemoryRoleBindingRepository()
constraints = InMemoryConstraintRepository()

identity = Identity.create_user(display_name="Alice", created_at=now)
identity.pull_events()
identity.activate(at=now)
identity.pull_events()
identities.save(identity)

tenant = Tenant.create(name="ACME", slug="acme", created_at=now)
tenant.pull_events()
tenant.activate(at=now)
tenant.pull_events()
tenants.save(tenant)

membership = Membership.create(
    identity_id=identity.id,
    tenant_id=tenant.id,
    created_at=now,
)
membership.pull_events()
membership.activate(at=now)
membership.pull_events()
memberships.save(membership)

permission = Permission(PermissionCode("payment.approve"), "Approve payments")
permissions.save(permission)

role = Role.create(
    name="Payment Approver",
    role_type=RoleType.TENANT,
    tenant_id=tenant.id,
    created_at=now,
)
role.pull_events()
role.add_permission(permission.code, at=now)
role.pull_events()
roles.save(role)

binding = RoleBinding.create(
    identity_id=identity.id,
    role_id=role.id,
    tenant_id=tenant.id,
    scope=TenantScope(tenant.id),
    created_at=now,
)
binding.pull_events()
bindings.save(binding)

constraints.save(
    MinimumAssuranceConstraint(
        id=GovernanceRuleId.new(),
        permission=permission.code,
        minimum_assurance=AssuranceLevel.AAL2,
        require_mfa=True,
        tenant_id=tenant.id,
    )
)

authorization = AuthorizationEngine(
    identity_repository=identities,
    tenant_repository=tenants,
    membership_repository=memberships,
    permission_repository=permissions,
    role_repository=roles,
    binding_repository=bindings,
    constraint_repository=constraints,
    clock=clock,
)

before_step_up = authorization.authorize(
    AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=permission.code,
        scope=TenantScope(tenant.id),
        authentication=AuthenticationEvidence(
            assurance_level=AssuranceLevel.AAL1,
            mfa=False,
            authenticated_at=now,
        ),
    )
)

assert before_step_up.reason_code is AuthorizationReason.DENY_STEP_UP_REQUIRED
assert before_step_up.step_up_required is True

after_step_up = authorization.authorize(
    AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=permission.code,
        scope=TenantScope(tenant.id),
        authentication=AuthenticationEvidence(
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=now,
        ),
    )
)

assert after_step_up.allowed is True

print(
    "Assurance-aware authorization OK:",
    before_step_up.reason_code.value,
    "->",
    after_step_up.reason_code.value,
)
