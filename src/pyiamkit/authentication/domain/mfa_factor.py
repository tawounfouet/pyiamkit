"""Multi-factor authentication factor aggregate."""

from datetime import datetime, timedelta

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent

from .errors import InvalidMfaFactor, InvalidMfaFactorTransition, MfaReplayDetected
from .events import AuthenticationEventType
from .value_objects import MfaFactorId, MfaFactorStatus, MfaFactorType


class MfaFactor:
    """Revocable MFA enrollment that stores only an opaque secret reference."""

    __slots__ = (
        "_activated_at",
        "_created_at",
        "_id",
        "_identity_id",
        "_label",
        "_last_accepted_counter",
        "_last_verified_at",
        "_pending_events",
        "_revoked_at",
        "_secret_reference",
        "_status",
        "_type",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        factor_id: MfaFactorId,
        version: int,
        identity_id: IdentityId,
        factor_type: MfaFactorType,
        status: MfaFactorStatus,
        secret_reference: str,
        created_at: datetime,
        updated_at: datetime,
        label: str | None = None,
        activated_at: datetime | None = None,
        revoked_at: datetime | None = None,
        last_verified_at: datetime | None = None,
        last_accepted_counter: int | None = None,
    ) -> None:
        for name, value in (
            ("created_at", created_at),
            ("updated_at", updated_at),
            ("activated_at", activated_at),
            ("revoked_at", revoked_at),
            ("last_verified_at", last_verified_at),
        ):
            if value is not None:
                self._require_utc(value, name)
        reference = secret_reference.strip()
        normalized_label = None if label is None else label.strip() or None
        if not reference:
            raise InvalidMfaFactor("secret_reference must not be empty")
        if last_accepted_counter is not None and last_accepted_counter < 0:
            raise InvalidMfaFactor("last_accepted_counter must be non-negative")
        if activated_at is not None and activated_at < created_at:
            raise InvalidMfaFactor("activated_at must not be before created_at")
        if revoked_at is not None and revoked_at < created_at:
            raise InvalidMfaFactor("revoked_at must not be before created_at")
        if last_verified_at is not None and last_verified_at < created_at:
            raise InvalidMfaFactor("last_verified_at must not be before created_at")

        self._id = factor_id
        self._version = version
        self._identity_id = identity_id
        self._type = factor_type
        self._status = status
        self._secret_reference = reference
        self._label = normalized_label
        self._created_at = created_at
        self._updated_at = updated_at
        self._activated_at = activated_at
        self._revoked_at = revoked_at
        self._last_verified_at = last_verified_at
        self._last_accepted_counter = last_accepted_counter
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        *,
        factor_id: MfaFactorId,
        identity_id: IdentityId,
        factor_type: MfaFactorType,
        secret_reference: str,
        created_at: datetime,
        label: str | None = None,
    ) -> "MfaFactor":
        factor = cls(
            factor_id=factor_id,
            version=0,
            identity_id=identity_id,
            factor_type=factor_type,
            status=MfaFactorStatus.PENDING,
            secret_reference=secret_reference,
            label=label,
            created_at=created_at,
            updated_at=created_at,
        )
        factor._record(AuthenticationEventType.MFA_FACTOR_CREATED, created_at)
        return factor

    @classmethod
    def _rehydrate(
        cls,
        *,
        factor_id: MfaFactorId,
        version: int,
        identity_id: IdentityId,
        factor_type: MfaFactorType,
        status: MfaFactorStatus,
        secret_reference: str,
        created_at: datetime,
        updated_at: datetime,
        label: str | None,
        activated_at: datetime | None,
        revoked_at: datetime | None,
        last_verified_at: datetime | None,
        last_accepted_counter: int | None,
    ) -> "MfaFactor":
        return cls(
            factor_id=factor_id,
            version=version,
            identity_id=identity_id,
            factor_type=factor_type,
            status=status,
            secret_reference=secret_reference,
            label=label,
            created_at=created_at,
            updated_at=updated_at,
            activated_at=activated_at,
            revoked_at=revoked_at,
            last_verified_at=last_verified_at,
            last_accepted_counter=last_accepted_counter,
        )

    @property
    def id(self) -> MfaFactorId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def type(self) -> MfaFactorType:
        return self._type

    @property
    def status(self) -> MfaFactorStatus:
        return self._status

    @property
    def secret_reference(self) -> str:
        return self._secret_reference

    @property
    def label(self) -> str | None:
        return self._label

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def activated_at(self) -> datetime | None:
        return self._activated_at

    @property
    def revoked_at(self) -> datetime | None:
        return self._revoked_at

    @property
    def last_verified_at(self) -> datetime | None:
        return self._last_verified_at

    @property
    def last_accepted_counter(self) -> int | None:
        return self._last_accepted_counter

    def is_active(self) -> bool:
        return self.status is MfaFactorStatus.ACTIVE

    def activate(self, *, at: datetime, counter: int) -> None:
        if self.status is not MfaFactorStatus.PENDING:
            raise InvalidMfaFactorTransition(self.status.value, "activate")
        self._accept_counter(counter=counter, at=at)
        self._status = MfaFactorStatus.ACTIVE
        self._activated_at = at
        self._touch(at)
        self._record(AuthenticationEventType.MFA_FACTOR_ACTIVATED, at)

    def record_verification(self, *, at: datetime, counter: int) -> None:
        if self.status is not MfaFactorStatus.ACTIVE:
            raise InvalidMfaFactorTransition(self.status.value, "verify")
        self._accept_counter(counter=counter, at=at)
        self._touch(at)
        self._record(AuthenticationEventType.MFA_FACTOR_VERIFIED, at)

    def revoke(self, *, at: datetime) -> None:
        if self.status is MfaFactorStatus.REVOKED:
            raise InvalidMfaFactorTransition(self.status.value, "revoke")
        self._require_utc(at, "at")
        self._status = MfaFactorStatus.REVOKED
        self._revoked_at = at
        self._touch(at)
        self._record(AuthenticationEventType.MFA_FACTOR_REVOKED, at)

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _accept_counter(self, *, counter: int, at: datetime) -> None:
        self._require_utc(at, "at")
        if counter < 0:
            raise InvalidMfaFactor("TOTP counter must be non-negative")
        if self.last_accepted_counter is not None and counter <= self.last_accepted_counter:
            raise MfaReplayDetected(self.id)
        self._last_accepted_counter = counter
        self._last_verified_at = at

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    def _record(self, event_type: AuthenticationEventType, at: datetime) -> None:
        self._pending_events.append(
            DomainEvent(
                event_type=event_type.value,
                occurred_at=at,
                metadata={
                    "factor_id": str(self.id),
                    "identity_id": str(self.identity_id),
                    "factor_type": self.type.value,
                },
            )
        )

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MfaFactor):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
