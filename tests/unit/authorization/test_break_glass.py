from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.audit import SecurityEvent, SecuritySeverity
from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthenticationEvidence,
    BreakGlassDenied,
    BreakGlassGrant,
    BreakGlassPolicy,
    BreakGlassService,
)
from pyiamkit.identity import IdentityId
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 10, 3, 8, 30, tzinfo=UTC)


class FrozenClock(Clock):
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class RecordingBreakGlassSink:
    def __init__(self) -> None:
        self.records: list[tuple[BreakGlassGrant, SecurityEvent]] = []

    def record(self, grant: BreakGlassGrant, event: SecurityEvent) -> None:
        self.records.append((grant, event))


class FailingBreakGlassSink:
    def record(self, grant: BreakGlassGrant, event: SecurityEvent) -> None:
        del grant, event
        raise RuntimeError("security evidence unavailable")


def _evidence(
    *,
    level: AssuranceLevel = AssuranceLevel.AAL2,
    mfa: bool = True,
) -> AuthenticationEvidence:
    return AuthenticationEvidence(
        assurance_level=level,
        mfa=mfa,
        authenticated_at=NOW - timedelta(minutes=5),
    )


def test_break_glass_activation_is_temporary_mfa_and_security_event_recorded() -> None:
    sink = RecordingBreakGlassSink()
    actor_id = IdentityId.new()
    tenant_id = TenantId.new()
    service = BreakGlassService(clock=FrozenClock(), sink=sink)

    grant = service.activate(
        actor_id=actor_id,
        tenant_id=tenant_id,
        authentication=_evidence(),
        justification="Production IAM recovery",
        duration=timedelta(minutes=10),
        reference="INC-2042",
    )

    assert grant.actor_id == actor_id
    assert grant.tenant_id == tenant_id
    assert grant.activated_at == NOW
    assert grant.expires_at == NOW + timedelta(minutes=10)
    assert grant.reference == "INC-2042"
    assert grant.is_active(at=NOW)
    assert grant.is_active(at=grant.expires_at - timedelta(microseconds=1))
    assert not grant.is_active(at=grant.expires_at)

    assert len(sink.records) == 1
    recorded_grant, event = sink.records[0]
    assert recorded_grant == grant
    assert event.event_type == "BreakGlassActivated"
    assert event.severity is SecuritySeverity.CRITICAL
    assert event.tenant_id == str(tenant_id)
    assert event.actor_id == str(actor_id)
    assert event.subject_id == str(actor_id)
    assert event.payload["break_glass_grant_id"] == str(grant.id)
    assert event.payload["expires_at"] == grant.expires_at.isoformat()
    assert event.payload["reference"] == "INC-2042"


@pytest.mark.parametrize(
    "evidence",
    [
        _evidence(mfa=False),
        _evidence(level=AssuranceLevel.AAL1, mfa=True),
    ],
)
def test_break_glass_activation_requires_mfa_and_minimum_assurance(
    evidence: AuthenticationEvidence,
) -> None:
    sink = RecordingBreakGlassSink()
    service = BreakGlassService(clock=FrozenClock(), sink=sink)

    with pytest.raises(BreakGlassDenied):
        service.activate(
            actor_id=IdentityId.new(),
            tenant_id=TenantId.new(),
            authentication=evidence,
            justification="Emergency recovery",
            duration=timedelta(minutes=5),
        )

    assert sink.records == []


@pytest.mark.parametrize(
    "duration",
    [timedelta(0), timedelta(seconds=-1), timedelta(minutes=16)],
)
def test_break_glass_duration_is_bounded_and_denied_before_recording(
    duration: timedelta,
) -> None:
    sink = RecordingBreakGlassSink()
    service = BreakGlassService(
        clock=FrozenClock(),
        sink=sink,
        policy=BreakGlassPolicy(max_duration=timedelta(minutes=15)),
    )

    with pytest.raises(BreakGlassDenied, match="duration"):
        service.activate(
            actor_id=IdentityId.new(),
            tenant_id=TenantId.new(),
            authentication=_evidence(),
            justification="Emergency recovery",
            duration=duration,
        )

    assert sink.records == []


def test_break_glass_recording_failure_prevents_successful_activation() -> None:
    service = BreakGlassService(clock=FrozenClock(), sink=FailingBreakGlassSink())

    with pytest.raises(RuntimeError, match="security evidence unavailable"):
        service.activate(
            actor_id=IdentityId.new(),
            tenant_id=TenantId.new(),
            authentication=_evidence(),
            justification="Emergency recovery",
            duration=timedelta(minutes=5),
        )


def test_break_glass_policy_can_require_aal3() -> None:
    sink = RecordingBreakGlassSink()
    service = BreakGlassService(
        clock=FrozenClock(),
        sink=sink,
        policy=BreakGlassPolicy(
            max_duration=timedelta(minutes=5),
            minimum_assurance=AssuranceLevel.AAL3,
        ),
    )

    with pytest.raises(BreakGlassDenied, match="aal3"):
        service.activate(
            actor_id=IdentityId.new(),
            tenant_id=TenantId.new(),
            authentication=_evidence(level=AssuranceLevel.AAL2),
            justification="Emergency recovery",
            duration=timedelta(minutes=5),
        )

    grant = service.activate(
        actor_id=IdentityId.new(),
        tenant_id=TenantId.new(),
        authentication=_evidence(level=AssuranceLevel.AAL3),
        justification="Emergency recovery",
        duration=timedelta(minutes=5),
    )
    assert grant.is_active(at=NOW)


def test_break_glass_fails_closed_for_non_utc_clock() -> None:
    sink = RecordingBreakGlassSink()
    service = BreakGlassService(
        clock=FrozenClock(datetime(2026, 10, 3, 8, 30)),
        sink=sink,
    )

    with pytest.raises(BreakGlassDenied, match="UTC-aware"):
        service.activate(
            actor_id=IdentityId.new(),
            tenant_id=TenantId.new(),
            authentication=_evidence(),
            justification="Emergency recovery",
            duration=timedelta(minutes=5),
        )

    assert sink.records == []


def test_break_glass_grant_is_context_only_not_an_rbac_assignment() -> None:
    sink = RecordingBreakGlassSink()
    service = BreakGlassService(clock=FrozenClock(), sink=sink)

    grant = service.activate(
        actor_id=IdentityId.new(),
        tenant_id=TenantId.new(),
        authentication=_evidence(),
        justification="Emergency recovery",
        duration=timedelta(minutes=5),
    )

    assert not hasattr(grant, "role_id")
    assert not hasattr(grant, "permissions")
    assert not hasattr(grant, "binding_id")
