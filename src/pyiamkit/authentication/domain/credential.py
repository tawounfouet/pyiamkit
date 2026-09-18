"""Credential aggregate without raw secret material."""

from collections.abc import Mapping
from datetime import datetime, timedelta
from types import MappingProxyType

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent

from .errors import InvalidCredential, InvalidCredentialTransition
from .events import AuthenticationEventType
from .value_objects import CredentialId, CredentialStatus, CredentialType


class Credential:
    """Authentication credential metadata referencing externally protected material."""

    __slots__ = (
        "_created_at",
        "_fingerprint",
        "_id",
        "_identity_id",
        "_label",
        "_metadata",
        "_pending_events",
        "_reference",
        "_revoked_at",
        "_status",
        "_type",
        "_updated_at",
        "_valid_from",
        "_valid_until",
        "_version",
    )

    def __init__(
        self,
        *,
        credential_id: CredentialId,
        version: int,
        identity_id: IdentityId,
        credential_type: CredentialType,
        status: CredentialStatus,
        reference: str,
        created_at: datetime,
        updated_at: datetime,
        valid_from: datetime,
        valid_until: datetime | None = None,
        fingerprint: str | None = None,
        label: str | None = None,
        revoked_at: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        self._require_utc(created_at, "created_at")
        self._require_utc(updated_at, "updated_at")
        self._require_utc(valid_from, "valid_from")
        if valid_until is not None:
            self._require_utc(valid_until, "valid_until")
            if valid_until <= valid_from:
                raise InvalidCredential("valid_until must be after valid_from.")
        if revoked_at is not None:
            self._require_utc(revoked_at, "revoked_at")
        reference = reference.strip()
        if not reference:
            raise InvalidCredential("Credential reference must not be empty.")
        fingerprint = None if fingerprint is None else fingerprint.strip() or None
        label = None if label is None else label.strip() or None
        self._id = credential_id
        self._version = version
        self._identity_id = identity_id
        self._type = credential_type
        self._status = status
        self._reference = reference
        self._fingerprint = fingerprint
        self._label = label
        self._created_at = created_at
        self._updated_at = updated_at
        self._valid_from = valid_from
        self._valid_until = valid_until
        self._revoked_at = revoked_at
        self._metadata = MappingProxyType(dict(metadata or {}))
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        *,
        identity_id: IdentityId,
        credential_type: CredentialType,
        reference: str,
        created_at: datetime,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        fingerprint: str | None = None,
        label: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> "Credential":
        credential = cls(
            credential_id=CredentialId.new(),
            version=0,
            identity_id=identity_id,
            credential_type=credential_type,
            status=CredentialStatus.ACTIVE,
            reference=reference,
            created_at=created_at,
            updated_at=created_at,
            valid_from=created_at if valid_from is None else valid_from,
            valid_until=valid_until,
            fingerprint=fingerprint,
            label=label,
            metadata=metadata,
        )
        credential._record(AuthenticationEventType.CREDENTIAL_CREATED, created_at)
        return credential

    @classmethod
    def _rehydrate(
        cls,
        *,
        credential_id: CredentialId,
        version: int,
        identity_id: IdentityId,
        credential_type: CredentialType,
        status: CredentialStatus,
        reference: str,
        created_at: datetime,
        updated_at: datetime,
        valid_from: datetime,
        valid_until: datetime | None,
        fingerprint: str | None,
        label: str | None,
        revoked_at: datetime | None,
        metadata: Mapping[str, object],
    ) -> "Credential":
        return cls(
            credential_id=credential_id,
            version=version,
            identity_id=identity_id,
            credential_type=credential_type,
            status=status,
            reference=reference,
            created_at=created_at,
            updated_at=updated_at,
            valid_from=valid_from,
            valid_until=valid_until,
            fingerprint=fingerprint,
            label=label,
            revoked_at=revoked_at,
            metadata=metadata,
        )

    @property
    def id(self) -> CredentialId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def type(self) -> CredentialType:
        return self._type

    @property
    def status(self) -> CredentialStatus:
        return self._status

    @property
    def reference(self) -> str:
        return self._reference

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

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
    def valid_from(self) -> datetime:
        return self._valid_from

    @property
    def valid_until(self) -> datetime | None:
        return self._valid_until

    @property
    def revoked_at(self) -> datetime | None:
        return self._revoked_at

    @property
    def metadata(self) -> Mapping[str, object]:
        return self._metadata

    def is_active(self, *, at: datetime) -> bool:
        self._require_utc(at, "at")
        return (
            self.status is CredentialStatus.ACTIVE
            and at >= self.valid_from
            and (self.valid_until is None or at < self.valid_until)
        )

    def revoke(self, *, at: datetime) -> None:
        if self.status is not CredentialStatus.ACTIVE:
            raise InvalidCredentialTransition(self.status.value, "revoke")
        self._require_utc(at, "at")
        self._status = CredentialStatus.REVOKED
        self._revoked_at = at
        self._touch(at)
        self._record(AuthenticationEventType.CREDENTIAL_REVOKED, at)

    def expire(self, *, at: datetime) -> None:
        if self.status is not CredentialStatus.ACTIVE:
            raise InvalidCredentialTransition(self.status.value, "expire")
        self._require_utc(at, "at")
        if self.valid_until is None or at < self.valid_until:
            raise InvalidCredential("Credential cannot expire before valid_until.")
        self._status = CredentialStatus.EXPIRED
        self._touch(at)
        self._record(AuthenticationEventType.CREDENTIAL_EXPIRED, at)

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    def _record(self, event_type: AuthenticationEventType, at: datetime) -> None:
        self._pending_events.append(
            DomainEvent(
                event_type=event_type.value,
                occurred_at=at,
                metadata={
                    "credential_id": str(self.id),
                    "identity_id": str(self.identity_id),
                    "credential_type": self.type.value,
                },
            )
        )

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Credential):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
