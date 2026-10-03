from datetime import UTC, datetime
from decimal import Decimal

import pytest

from pyiamkit.audit import (
    GenericSecurityEventExporter,
    OutboxEvent,
    SecurityEvent,
    SecurityEventEnvelope,
    SecuritySeverity,
    security_event_to_outbox,
)
from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AccessGovernanceApplicationService,
    AuthenticationEvidence,
    AuthorizationDecision,
    AuthorizationEngine,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    ResourceDescriptor,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryConstraintRepository,
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
    InMemorySoDRuleRepository,
)
from pyiamkit.conformance import (
    EventPublisherConformance,
    EventPublisherProbe,
    PolicyEvaluatorConformance,
    PolicyEvaluatorProbe,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository

NOW = datetime(2026, 10, 3, 9, 45, tzinfo=UTC)
PERMISSION = PermissionCode("payment.approve")

pytestmark = pytest.mark.conformance


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _policy_runtime():
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    constraints = InMemoryConstraintRepository()
    sod = InMemorySoDRuleRepository()
    events = InMemoryDomainEventSink()

    identity = Identity.create_user(display_name="Policy Subject", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identities.save(identity)

    tenant = Tenant.create(name="Policy Tenant", slug="policy-tenant", created_at=NOW)
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

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
    )
    binding.pull_events()
    bindings.save(binding)

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


def _request(
    identity: Identity,
    tenant: Tenant,
    *,
    attributes: dict[str, object],
    authentication: AuthenticationEvidence | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=PERMISSION,
        scope=TenantScope(tenant.id),
        resource=ResourceDescriptor(
            "payment",
            "PAY-CONFORMANCE",
            tenant.id,
            attributes=attributes,
        ),
        authentication=authentication,
    )


def _matching_policy_context() -> AuthorizationDecision:
    engine, governance, identity, tenant = _policy_runtime()
    governance.register_numeric_maximum(
        str(PERMISSION),
        resource_attribute="amount",
        maximum=Decimal("100"),
    )
    return engine.authorize(_request(identity, tenant, attributes={"amount": "50"}))


def _constraint_violation() -> AuthorizationDecision:
    engine, governance, identity, tenant = _policy_runtime()
    governance.register_numeric_maximum(
        str(PERMISSION),
        resource_attribute="amount",
        maximum=Decimal("100"),
    )
    return engine.authorize(_request(identity, tenant, attributes={"amount": "150"}))


def _missing_policy_context() -> AuthorizationDecision:
    engine, governance, identity, tenant = _policy_runtime()
    governance.register_numeric_maximum(
        str(PERMISSION),
        resource_attribute="amount",
        maximum=Decimal("100"),
    )
    return engine.authorize(_request(identity, tenant, attributes={}))


def _dynamic_sod_conflict() -> AuthorizationDecision:
    engine, governance, identity, tenant = _policy_runtime()
    governance.register_distinct_actor_sod(
        str(PERMISSION),
        name="No self approval",
        resource_attribute="prepared_by",
    )
    return engine.authorize(
        _request(
            identity,
            tenant,
            attributes={"prepared_by": str(identity.id)},
        )
    )


def _step_up_required() -> AuthorizationDecision:
    engine, governance, identity, tenant = _policy_runtime()
    governance.register_minimum_assurance(
        str(PERMISSION),
        minimum_assurance=AssuranceLevel.AAL2,
        require_mfa=True,
    )
    return engine.authorize(
        _request(
            identity,
            tenant,
            attributes={},
            authentication=AuthenticationEvidence(
                assurance_level=AssuranceLevel.AAL1,
                mfa=False,
                authenticated_at=NOW,
            ),
        )
    )


def test_policy_evaluator_conformance_qualifies_live_governance_model() -> None:
    report = PolicyEvaluatorConformance(
        PolicyEvaluatorProbe(
            name="AuthorizationGovernance[InMemory]",
            matching_context=_matching_policy_context,
            constraint_violation=_constraint_violation,
            missing_context=_missing_policy_context,
            dynamic_sod_conflict=_dynamic_sod_conflict,
            step_up_required=_step_up_required,
        )
    ).run()

    report.require_passed()
    assert report.passed is True


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityEventEnvelope] = []

    def emit(self, event: SecurityEventEnvelope) -> None:
        self.events.append(event)


class FailingSink:
    def emit(self, event: SecurityEventEnvelope) -> None:
        del event
        raise RuntimeError("downstream unavailable")


def _security_event() -> SecurityEvent:
    return SecurityEvent(
        event_type="AuthorizationDenied",
        severity=SecuritySeverity.HIGH,
        occurred_at=NOW,
        tenant_id="tenant-1",
        actor_id="actor-1",
        subject_id="subject-1",
        correlation_id="corr-1",
        payload={"reason": "policy"},
    )


def _publish_once() -> tuple[str, str]:
    event = _security_event()
    sink = RecordingSink()
    GenericSecurityEventExporter(sink).publish(security_event_to_outbox(event))
    return str(event.id), sink.events[0].event_id


def _publish_duplicate() -> tuple[str, tuple[str, ...]]:
    event = _security_event()
    outbox = security_event_to_outbox(event)
    sink = RecordingSink()
    exporter = GenericSecurityEventExporter(sink)
    exporter.publish(outbox)
    exporter.publish(outbox)
    return str(event.id), tuple(item.event_id for item in sink.events)


def _publish_invalid() -> None:
    GenericSecurityEventExporter(RecordingSink()).publish(
        OutboxEvent(
            event_type="IdentityCreated",
            occurred_at=NOW,
            payload={"identity_id": "identity-1"},
        )
    )


def _publish_downstream_failure() -> None:
    GenericSecurityEventExporter(FailingSink()).publish(
        security_event_to_outbox(_security_event())
    )


def test_event_publisher_conformance_qualifies_generic_siem_exporter() -> None:
    report = EventPublisherConformance(
        EventPublisherProbe(
            name="GenericSecurityEventExporter",
            publish_once=_publish_once,
            publish_duplicate=_publish_duplicate,
            invalid_event=_publish_invalid,
            downstream_failure=_publish_downstream_failure,
            downstream_error=RuntimeError,
        )
    ).run()

    report.require_passed()
    assert report.passed is True
