"""Authentication session aggregate."""

from datetime import datetime, timedelta

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent

from .context import AuthenticationContext
from .errors import InvalidSession, InvalidSessionTransition
from .events import AuthenticationEventType
from .value_objects import SessionId, SessionStatus


class Session:
    """Revocable authenticated session with an explicit assurance context."""

    __slots__ = (
        "_context",
        "_created_at",
        "_expires_at",
        "_id",
        "_identity_id",
        "_last_activity_at",
        "_pending_events",
        "_revocation_reason",
        "_revoked_at",
        "_status",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        session_id: SessionId,
        version: int,
        identity_id: IdentityId,
        status: SessionStatus,
        context: AuthenticationContext,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        last_activity_at: datetime,
        revoked_at: datetime | None = None,
        revocation_reason: str | None = None,
    ) -> None:
        for name, value in (
            ("created_at", created_at),
            ("updated_at", updated_at),
            ("expires_at", expires_at),
            ("last_activity_at", last_activity_at),
        ):
            self._require_utc(value, name)
        if revoked_at is not None:
            self._require_utc(revoked_at, "revoked_at")
        if expires_at <= created_at:
            raise InvalidSession("expires_at must be after created_at.")
        if context.authenticated_at > created_at:
            raise InvalidSession("Authentication context cannot occur after session creation.")
        if last_activity_at < created_at or last_activity_at > updated_at:
            raise InvalidSession("last_activity_at must be inside the session lifetime.")
        revocation_reason = None if revocation_reason is None else revocation_reason.strip() or None
        self._id = session_id
        self._version = version
        self._identity_id = identity_id
        self._status = status
        self._context = context
        self._created_at = created_at
        self._updated_at = updated_at
        self._expires_at = expires_at
        self._last_activity_at = last_activity_at
        self._revoked_at = revoked_at
        self._revocation_reason = revocation_reason
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def open(
        cls,
        *,
        identity_id: IdentityId,
        context: AuthenticationContext,
        created_at: datetime,
        expires_at: datetime,
    ) -> "Session":
        session = cls(
            session_id=SessionId.new(),
            version=0,
            identity_id=identity_id,
            status=SessionStatus.ACTIVE,
            context=context,
            created_at=created_at,
            updated_at=created_at,
            expires_at=expires_at,
            last_activity_at=created_at,
        )
        session._record(AuthenticationEventType.SESSION_OPENED, created_at)
        return session

    @classmethod
    def _rehydrate(
        cls,
        *,
        session_id: SessionId,
        version: int,
        identity_id: IdentityId,
        status: SessionStatus,
        context: AuthenticationContext,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        last_activity_at: datetime,
        revoked_at: datetime | None,
        revocation_reason: str | None,
    ) -> "Session":
        return cls(
            session_id=session_id,
            version=version,
            identity_id=identity_id,
            status=status,
            context=context,
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
            last_activity_at=last_activity_at,
            revoked_at=revoked_at,
            revocation_reason=revocation_reason,
        )

    @property
    def id(self) -> SessionId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def status(self) -> SessionStatus:
        return self._status

    @property
    def context(self) -> AuthenticationContext:
        return self._context

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def last_activity_at(self) -> datetime:
        return self._last_activity_at

    @property
    def revoked_at(self) -> datetime | None:
        return self._revoked_at

    @property
    def revocation_reason(self) -> str | None:
        return self._revocation_reason

    def is_active(self, *, at: datetime) -> bool:
        self._require_utc(at, "at")
        return self.status is SessionStatus.ACTIVE and at < self.expires_at

    def touch(self, *, at: datetime) -> None:
        if not self.is_active(at=at):
            raise InvalidSessionTransition(self.status.value, "touch")
        if at < self.last_activity_at:
            raise InvalidSession("Session activity cannot move backwards in time.")
        self._last_activity_at = at
        self._touch(at)
        self._record(AuthenticationEventType.SESSION_TOUCHED, at)

    def revoke(self, *, at: datetime, reason: str | None = None) -> None:
        if self.status is not SessionStatus.ACTIVE:
            raise InvalidSessionTransition(self.status.value, "revoke")
        self._require_utc(at, "at")
        reason = None if reason is None else reason.strip() or None
        self._status = SessionStatus.REVOKED
        self._revoked_at = at
        self._revocation_reason = reason
        self._touch(at)
        self._record(AuthenticationEventType.SESSION_REVOKED, at)

    def expire(self, *, at: datetime) -> None:
        if self.status is not SessionStatus.ACTIVE:
            raise InvalidSessionTransition(self.status.value, "expire")
        self._require_utc(at, "at")
        if at < self.expires_at:
            raise InvalidSession("Session cannot expire before expires_at.")
        self._status = SessionStatus.EXPIRED
        self._touch(at)
        self._record(AuthenticationEventType.SESSION_EXPIRED, at)

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
                    "session_id": str(self.id),
                    "identity_id": str(self.identity_id),
                    "authentication_method": self.context.method.value,
                    "assurance_level": self.context.assurance_level.value,
                },
            )
        )

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Session):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
