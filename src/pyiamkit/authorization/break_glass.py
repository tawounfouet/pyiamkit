"""Fail-closed break-glass foundations for emergency privileged access."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from pyiamkit.audit import SecurityEvent, SecuritySeverity
from pyiamkit.authentication import AssuranceLevel
from pyiamkit.identity import IdentityId
from pyiamkit.shared import Clock, EntityId
from pyiamkit.tenancy import TenantId

from .domain.decision import AuthenticationEvidence
from .domain.errors import AuthorizationModelError


class BreakGlassError(AuthorizationModelError):
    """Base break-glass activation error."""

    code = "BREAK_GLASS_ERROR"


class BreakGlassDenied(BreakGlassError):
    """Raised when an emergency activation does not satisfy security policy."""

    code = "BREAK_GLASS_DENIED"


class BreakGlassGrantId(EntityId):
    """Opaque identifier for one emergency-access activation."""


@dataclass(frozen=True, slots=True)
class BreakGlassPolicy:
    """Local emergency-access policy with a strict maximum lifetime."""

    max_duration: timedelta = timedelta(minutes=15)
    minimum_assurance: AssuranceLevel = AssuranceLevel.AAL2

    def __post_init__(self) -> None:
        if self.max_duration <= timedelta(0):
            raise ValueError("BreakGlassPolicy.max_duration must be positive")


@dataclass(frozen=True, slots=True)
class BreakGlassGrant:
    """Temporary emergency-access evidence; never an RBAC grant by itself."""

    id: BreakGlassGrantId
    actor_id: IdentityId
    tenant_id: TenantId
    justification: str
    activated_at: datetime
    expires_at: datetime
    reference: str | None = None

    def __post_init__(self) -> None:
        justification = self.justification.strip()
        if not justification:
            raise ValueError("BreakGlassGrant.justification must not be empty")
        if self.activated_at.tzinfo is None or self.activated_at.utcoffset() != timedelta(0):
            raise ValueError("BreakGlassGrant.activated_at must be UTC-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() != timedelta(0):
            raise ValueError("BreakGlassGrant.expires_at must be UTC-aware")
        if self.expires_at <= self.activated_at:
            raise ValueError("BreakGlassGrant.expires_at must be after activated_at")
        reference = None if self.reference is None else self.reference.strip() or None
        object.__setattr__(self, "justification", justification)
        object.__setattr__(self, "reference", reference)

    def is_active(self, *, at: datetime) -> bool:
        if at.tzinfo is None or at.utcoffset() != timedelta(0):
            raise ValueError("BreakGlassGrant activity check must use a UTC-aware datetime")
        return self.activated_at <= at < self.expires_at


class BreakGlassActivationSink(Protocol):
    """Mandatory recording boundary for one emergency activation."""

    def record(self, grant: BreakGlassGrant, event: SecurityEvent) -> None: ...


class BreakGlassService:
    """Authorize and record temporary emergency-access context."""

    def __init__(
        self,
        *,
        clock: Clock,
        sink: BreakGlassActivationSink,
        policy: BreakGlassPolicy | None = None,
    ) -> None:
        self._clock = clock
        self._sink = sink
        self._policy = BreakGlassPolicy() if policy is None else policy

    def activate(
        self,
        *,
        actor_id: IdentityId,
        tenant_id: TenantId,
        authentication: AuthenticationEvidence,
        justification: str,
        duration: timedelta,
        reference: str | None = None,
    ) -> BreakGlassGrant:
        if duration <= timedelta(0):
            raise BreakGlassDenied("Break-glass duration must be positive")
        if duration > self._policy.max_duration:
            raise BreakGlassDenied("Break-glass duration exceeds configured maximum")
        if not authentication.mfa:
            raise BreakGlassDenied("Break-glass activation requires MFA")
        if _assurance_rank(authentication.assurance_level) < _assurance_rank(
            self._policy.minimum_assurance
        ):
            raise BreakGlassDenied(
                f"Break-glass activation requires assurance level "
                f"{self._policy.minimum_assurance.value}"
            )

        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise BreakGlassDenied("Break-glass clock must return a UTC-aware datetime")

        grant = BreakGlassGrant(
            id=BreakGlassGrantId.new(),
            actor_id=actor_id,
            tenant_id=tenant_id,
            justification=justification,
            activated_at=now,
            expires_at=now + duration,
            reference=reference,
        )
        event = SecurityEvent(
            event_type="BreakGlassActivated",
            severity=SecuritySeverity.CRITICAL,
            occurred_at=now,
            tenant_id=str(tenant_id),
            actor_id=str(actor_id),
            subject_id=str(actor_id),
            payload={
                "break_glass_grant_id": str(grant.id),
                "expires_at": grant.expires_at.isoformat(),
                "justification": grant.justification,
                "reference": grant.reference,
            },
        )

        self._sink.record(grant, event)
        return grant


def _assurance_rank(level: AssuranceLevel) -> int:
    return {
        AssuranceLevel.AAL1: 1,
        AssuranceLevel.AAL2: 2,
        AssuranceLevel.AAL3: 3,
    }[level]
