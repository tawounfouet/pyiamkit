from datetime import UTC, datetime

from pyiamkit.audit import AuditOutcome
from pyiamkit.audit.adapters import InMemoryAuditRepository
from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    ExplanationLevel,
    Permission,
    PermissionCode,
    ResourceDescriptor,
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
PERMISSION = PermissionCode("invoice.read")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _setup(*, include_permission: bool = True):
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    audit = InMemoryAuditRepository()

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

    permissions.save(Permission(PERMISSION, "Read invoices"))
    role = Role.create(
        name="Invoice Reader", role_type=RoleType.TENANT, tenant_id=tenant.id, created_at=NOW
    )
    role.pull_events()
    if include_permission:
        role.add_permission(PERMISSION, at=NOW)
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
        audit_sink=audit,
    )
    request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=PERMISSION,
        scope=TenantScope(tenant.id),
        resource=ResourceDescriptor(
            "invoice", "INV-001", tenant.id, attributes={"secret": "must-not-be-audited"}
        ),
        correlation_id="corr-123",
    )
    return engine, request, audit, role, binding


def test_allow_decision_is_audited_without_resource_attributes() -> None:
    engine, request, audit, role, binding = _setup()
    decision = engine.authorize(request)

    event = audit.all()[0]
    assert event.outcome is AuditOutcome.ALLOW
    assert event.reason_code == AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH.value
    assert event.correlation_id == "corr-123"
    assert event.resource_type == "invoice"
    assert event.resource_id == "INV-001"
    assert event.metadata["decision_id"] == str(decision.id)
    assert event.metadata["bound_role_id"] == str(role.id)
    assert event.metadata["matched_binding_id"] == str(binding.id)
    assert "secret" not in event.metadata
    assert "must-not-be-audited" not in repr(event.metadata)


def test_deny_decision_is_also_audited() -> None:
    engine, request, audit, _, _ = _setup(include_permission=False)
    decision = engine.authorize(request)

    event = audit.all()[0]
    assert decision.allowed is False
    assert event.outcome is AuditOutcome.DENY
    assert event.reason_code == AuthorizationReason.DENY_PERMISSION_NOT_GRANTED.value


def test_summary_explanation_hides_internal_path_and_detailed_keeps_it() -> None:
    engine, request, _, _, _ = _setup()
    decision = engine.authorize(request)

    summary = decision.explanation()
    detailed = decision.explanation(ExplanationLevel.DETAILED)
    assert summary.allowed is True
    assert summary.details == ()
    assert summary.summary == "Access allowed."
    assert detailed.details == decision.explanation_path
    assert any(item.startswith("binding:") for item in detailed.details)


def test_engine_describe_returns_safe_summary() -> None:
    engine, request, _, _, _ = _setup(include_permission=False)
    explanation = engine.describe(request)
    assert explanation.allowed is False
    assert explanation.summary == "Access denied."
    assert explanation.reason_code is AuthorizationReason.DENY_PERMISSION_NOT_GRANTED
