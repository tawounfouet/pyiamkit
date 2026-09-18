"""Multi-factor enrollment, verification and Session step-up orchestration."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pyiamkit.identity import IdentityId, IdentityNotFound, IdentityRepository, IdentityStatus
from pyiamkit.shared import Clock, DomainEventSink

from .domain.errors import (
    AuthenticationSubjectInactive,
    MfaFactorNotFound,
    MfaFactorOwnershipMismatch,
    MfaVerificationFailed,
)
from .domain.mfa_factor import MfaFactor
from .domain.session import Session
from .domain.value_objects import (
    AssuranceLevel,
    MfaFactorId,
    MfaFactorStatus,
    MfaFactorType,
    SessionId,
)
from .ports import MfaFactorRepository, SessionRepository


@dataclass(frozen=True, slots=True)
class TotpEnrollmentMaterial:
    """One-time enrollment material returned to the host application."""

    secret_reference: str
    provisioning_uri: str

    def __post_init__(self) -> None:
        if not self.secret_reference.strip():
            raise ValueError("secret_reference must not be empty")
        if not self.provisioning_uri.strip():
            raise ValueError("provisioning_uri must not be empty")


@dataclass(frozen=True, slots=True)
class TotpEnrollment:
    factor: MfaFactor
    provisioning_uri: str


class MfaSecretStore(Protocol):
    """Secret-storage boundary used by MFA adapters."""

    def put(self, reference: str, secret: str) -> None: ...
    def get(self, reference: str) -> str | None: ...
    def delete(self, reference: str) -> None: ...


class TotpProvider(Protocol):
    """External secret-backed TOTP operations."""

    def begin_enrollment(
        self,
        *,
        factor_id: MfaFactorId,
        account_name: str,
    ) -> TotpEnrollmentMaterial: ...

    def verify(
        self,
        *,
        secret_reference: str,
        code: str,
        at: datetime,
        minimum_counter_exclusive: int | None,
    ) -> int | None: ...

    def delete(self, secret_reference: str) -> None: ...


class MfaApplicationService:
    """Coordinates TOTP factor lifecycle and assurance step-up."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        factor_repository: MfaFactorRepository,
        session_repository: SessionRepository,
        totp_provider: TotpProvider,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._identities = identity_repository
        self._factors = factor_repository
        self._sessions = session_repository
        self._totp = totp_provider
        self._clock = clock
        self._events = event_sink

    def begin_totp_enrollment(
        self,
        *,
        identity_id: IdentityId,
        account_name: str,
        label: str | None = None,
    ) -> TotpEnrollment:
        self._require_active_identity(identity_id)
        factor_id = MfaFactorId.new()
        material = self._totp.begin_enrollment(
            factor_id=factor_id,
            account_name=account_name,
        )
        factor = MfaFactor.create(
            factor_id=factor_id,
            identity_id=identity_id,
            factor_type=MfaFactorType.TOTP,
            secret_reference=material.secret_reference,
            label=label,
            created_at=self._clock.now(),
        )
        try:
            saved = self._save_factor(factor)
        except Exception:
            self._totp.delete(material.secret_reference)
            raise
        return TotpEnrollment(
            factor=saved,
            provisioning_uri=material.provisioning_uri,
        )

    def confirm_totp_enrollment(
        self,
        factor_id: MfaFactorId,
        *,
        code: str,
    ) -> MfaFactor:
        factor = self._require_factor(factor_id)
        if factor.status is not MfaFactorStatus.PENDING:
            raise MfaVerificationFailed("MFA factor is not pending enrollment")
        now = self._clock.now()
        counter = self._verify_totp(factor, code=code, at=now)
        factor.activate(at=now, counter=counter)
        return self._save_factor(factor)

    def verify_totp(
        self,
        factor_id: MfaFactorId,
        *,
        code: str,
    ) -> MfaFactor:
        factor = self._require_factor(factor_id)
        if not factor.is_active():
            raise MfaVerificationFailed("MFA factor is not active")
        now = self._clock.now()
        counter = self._verify_totp(factor, code=code, at=now)
        factor.record_verification(at=now, counter=counter)
        return self._save_factor(factor)

    def step_up_totp_session(
        self,
        session_id: SessionId,
        *,
        factor_id: MfaFactorId,
        code: str,
    ) -> Session:
        session = self._require_session(session_id)
        factor = self._require_factor(factor_id)
        if session.identity_id != factor.identity_id:
            raise MfaFactorOwnershipMismatch(factor.id, session.identity_id)
        if not factor.is_active():
            raise MfaVerificationFailed("MFA factor is not active")
        now = self._clock.now()
        if not session.is_active(at=now):
            raise MfaVerificationFailed("Session is not active")
        counter = self._verify_totp(factor, code=code, at=now)
        factor.record_verification(at=now, counter=counter)
        session.step_up(
            assurance_level=AssuranceLevel.AAL2,
            factor_id=factor.id,
            at=now,
        )
        self._save_factor(factor)
        return self._save_session(session)

    def revoke_factor(self, factor_id: MfaFactorId) -> MfaFactor:
        factor = self._require_factor(factor_id)
        factor.revoke(at=self._clock.now())
        saved = self._save_factor(factor)
        self._totp.delete(saved.secret_reference)
        return saved

    def factors_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        return self._factors.find_for_identity(identity_id)

    def active_factors_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        return self._factors.find_active_for_identity(identity_id)

    def _verify_totp(self, factor: MfaFactor, *, code: str, at: datetime) -> int:
        counter = self._totp.verify(
            secret_reference=factor.secret_reference,
            code=code,
            at=at,
            minimum_counter_exclusive=factor.last_accepted_counter,
        )
        if counter is None:
            raise MfaVerificationFailed("TOTP code is invalid or already used")
        return counter

    def _require_active_identity(self, identity_id: IdentityId) -> None:
        identity = self._identities.get(identity_id)
        if identity is None:
            raise IdentityNotFound(identity_id)
        if identity.status is not IdentityStatus.ACTIVE:
            raise AuthenticationSubjectInactive(identity_id)

    def _require_factor(self, factor_id: MfaFactorId) -> MfaFactor:
        factor = self._factors.get(factor_id)
        if factor is None:
            raise MfaFactorNotFound(factor_id)
        return factor

    def _require_session(self, session_id: SessionId) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            from .domain.errors import SessionNotFound

            raise SessionNotFound(session_id)
        return session

    def _save_factor(self, factor: MfaFactor) -> MfaFactor:
        events = factor.pull_events()
        self._factors.save(factor)
        self._events.publish(events)
        saved = self._factors.get(factor.id)
        if saved is None:
            raise RuntimeError("MFA factor repository did not return persisted aggregate")
        return saved

    def _save_session(self, session: Session) -> Session:
        events = session.pull_events()
        self._sessions.save(session)
        self._events.publish(events)
        saved = self._sessions.get(session.id)
        if saved is None:
            raise RuntimeError("Session repository did not return persisted aggregate")
        return saved
