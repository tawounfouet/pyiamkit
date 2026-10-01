from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import RoleBindingId
from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    InvalidationEvent,
    InvalidationKind,
    RevocationMarker,
    RevocationRegistryUnavailable,
    RevocationTargetType,
    SecurityStateMutationEventSink,
    StateVersion,
)
from pyiamkit.operations.adapters import (
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)
from pyiamkit.shared import DomainEvent, DomainEventSink
from pyiamkit.tenancy import MembershipId, TenantId

NOW = datetime(2026, 10, 1, 18, 30, tzinfo=UTC)


class RecordingSink(DomainEventSink):
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def publish(self, events: Sequence[DomainEvent]) -> None:
        self.events.extend(events)


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[InvalidationEvent] = []

    def publish(self, event: InvalidationEvent) -> None:
        self.events.append(event)


class UnavailableRevocations:
    def record(self, marker: RevocationMarker) -> None:
        del marker
        raise RevocationRegistryUnavailable("redis unavailable")

    def get(
        self,
        target_type: RevocationTargetType,
        target_id: str,
    ) -> RevocationMarker | None:
        del target_type, target_id
        return None

    def is_revoked(
        self,
        target_type: RevocationTargetType,
        target_id: str,
        *,
        at: datetime,
    ) -> bool:
        del target_type, target_id, at
        return False


def _event(event_type: str, **metadata: object) -> DomainEvent:
    return DomainEvent(
        event_type=event_type,
        occurred_at=NOW,
        metadata=metadata,
    )


def _sink(
    *,
    revocations: InMemoryRevocationRegistry | UnavailableRevocations | None = None,
) -> tuple[
    SecurityStateMutationEventSink,
    InMemorySecurityStateStore,
    RecordingSink,
    RecordingPublisher,
]:
    state = InMemorySecurityStateStore()
    downstream = RecordingSink()
    publisher = RecordingPublisher()
    sink = SecurityStateMutationEventSink(
        downstream,
        state_writer=state,
        invalidation_publisher=publisher,
        revocations=revocations,
    )
    return sink, state, downstream, publisher


def test_identity_security_mutation_bumps_state_and_records_revocation() -> None:
    revocations = InMemoryRevocationRegistry()
    sink, state, downstream, publisher = _sink(revocations=revocations)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    event = _event("IdentitySuspended", identity_id=str(identity_id))

    sink.publish((event,))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    marker = revocations.get(RevocationTargetType.IDENTITY, str(identity_id))
    assert stamp.identity == StateVersion(1)
    assert marker is not None
    assert marker.source_version == StateVersion(1)
    assert marker.reason_code == "IdentitySuspended"
    assert downstream.events == [event]
    assert publisher.events[0].event_id == event.event_id
    assert publisher.events[0].kind is InvalidationKind.IDENTITY


def test_identity_reactivation_advances_version_without_new_revocation() -> None:
    revocations = InMemoryRevocationRegistry()
    sink, state, _, _ = _sink(revocations=revocations)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    sink.publish((_event("IdentitySuspended", identity_id=str(identity_id)),))
    original = revocations.get(RevocationTargetType.IDENTITY, str(identity_id))
    sink.publish((_event("IdentityReactivated", identity_id=str(identity_id)),))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.identity == StateVersion(2)
    assert revocations.get(RevocationTargetType.IDENTITY, str(identity_id)) == original
    assert original is not None
    assert original.applies_to(stamp.identity) is False


def test_tenant_mutation_bumps_tenant_and_records_deny_fast_marker() -> None:
    revocations = InMemoryRevocationRegistry()
    sink, state, _, publisher = _sink(revocations=revocations)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    event = _event("TenantDisabled", tenant_id=str(tenant_id))

    sink.publish((event,))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    marker = revocations.get(RevocationTargetType.TENANT, str(tenant_id))
    assert stamp.tenant == StateVersion(1)
    assert marker is not None
    assert marker.tenant_id == tenant_id
    assert publisher.events[0].tenant_id == tenant_id


def test_membership_mutation_is_scoped_to_subject_and_tenant() -> None:
    revocations = InMemoryRevocationRegistry()
    sink, state, _, publisher = _sink(revocations=revocations)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    membership_id = MembershipId.new()
    event = _event(
        "MembershipRevoked",
        membership_id=str(membership_id),
        identity_id=str(identity_id),
        tenant_id=str(tenant_id),
    )

    sink.publish((event,))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    marker = revocations.get(RevocationTargetType.MEMBERSHIP, str(membership_id))
    assert stamp.membership == StateVersion(1)
    assert marker is not None
    assert marker.source_version == stamp.membership
    assert publisher.events[0].target_id == str(identity_id)
    assert publisher.events[0].tenant_id == tenant_id


def test_role_binding_mutation_bumps_subject_authorization() -> None:
    revocations = InMemoryRevocationRegistry()
    sink, state, _, publisher = _sink(revocations=revocations)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    binding_id = RoleBindingId.new()
    event = _event(
        "RoleBindingSuspended",
        binding_id=str(binding_id),
        identity_id=str(identity_id),
        tenant_id=str(tenant_id),
    )

    sink.publish((event,))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    marker = revocations.get(RevocationTargetType.ROLE_BINDING, str(binding_id))
    assert stamp.subject_authorization == StateVersion(1)
    assert marker is not None
    assert marker.source_version == stamp.subject_authorization
    assert publisher.events[0].kind is InvalidationKind.AUTHORIZATION


def test_tenant_role_mutation_bumps_tenant_authorization() -> None:
    sink, state, _, publisher = _sink()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    sink.publish(
        (
            _event(
                "RolePermissionAdded",
                role_id="role-1",
                role_type="tenant",
                tenant_id=str(tenant_id),
            ),
        )
    )

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.tenant_authorization == StateVersion(1)
    assert stamp.global_authorization == StateVersion(0)
    assert publisher.events[0].target_id == str(tenant_id)


def test_global_role_and_permission_mutations_bump_global_authorization() -> None:
    sink, state, _, publisher = _sink()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    sink.publish(
        (
            _event("RoleDisabled", role_id="role-1", role_type="global", tenant_id=None),
            _event("PermissionRegistered", permission="invoice.read"),
        )
    )

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.global_authorization == StateVersion(2)
    assert [event.target_id for event in publisher.events] == ["global", "global"]


def test_tenant_and_global_governance_use_distinct_invalidation_dimensions() -> None:
    sink, state, _, publisher = _sink()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    sink.publish(
        (
            _event(
                "AuthorizationConstraintRegistered",
                rule_id="rule-1",
                tenant_id=str(tenant_id),
            ),
            _event("StaticSoDRuleRegistered", rule_id="rule-2", tenant_id=None),
        )
    )

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.governance == StateVersion(1)
    assert stamp.runtime_generation == StateVersion(1)
    assert [event.kind for event in publisher.events] == [
        InvalidationKind.GOVERNANCE,
        InvalidationKind.GOVERNANCE,
    ]


def test_authentication_mutations_bump_authentication_but_session_touch_does_not() -> None:
    sink, state, downstream, publisher = _sink()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    sink.publish(
        (
            _event("SessionTouched", identity_id=str(identity_id), session_id="session-1"),
            _event("SessionSteppedUp", identity_id=str(identity_id), session_id="session-1"),
            _event("ExternalIdentityLinked", identity_id=str(identity_id)),
        )
    )

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.authentication == StateVersion(2)
    assert len(downstream.events) == 3
    assert len(publisher.events) == 2
    assert all(event.kind is InvalidationKind.AUTHENTICATION for event in publisher.events)


def test_unknown_domain_event_is_forwarded_without_security_bump() -> None:
    sink, state, downstream, publisher = _sink()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    event = _event("UnrelatedBusinessEvent", aggregate_id="x")

    sink.publish((event,))

    assert downstream.events == [event]
    assert publisher.events == []
    assert state.stamp_for(identity_id=identity_id, tenant_id=tenant_id) == (
        state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    )


def test_known_security_event_requires_scope_metadata_before_forwarding() -> None:
    sink, _, downstream, publisher = _sink()

    with pytest.raises(ValueError, match="identity_id"):
        sink.publish((_event("IdentitySuspended"),))

    assert downstream.events == []
    assert publisher.events == []


def test_revocation_registry_outage_does_not_block_authoritative_bump() -> None:
    sink, state, downstream, publisher = _sink(revocations=UnavailableRevocations())
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    event = _event("IdentityDisabled", identity_id=str(identity_id))

    sink.publish((event,))

    stamp = state.stamp_for(identity_id=identity_id, tenant_id=tenant_id)
    assert stamp.identity == StateVersion(1)
    assert downstream.events == [event]
    assert publisher.events[0].state_version == StateVersion(1)
