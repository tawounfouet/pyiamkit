"""Application orchestration for Credentials and Sessions."""

from collections.abc import Mapping
from datetime import datetime

from pyiamkit.identity import IdentityId, IdentityNotFound, IdentityRepository, IdentityStatus
from pyiamkit.shared import Clock, DomainEventSink

from .domain.context import AuthenticationContext
from .domain.credential import Credential
from .domain.errors import (
    AuthenticationSubjectInactive,
    CredentialAlreadyExists,
    CredentialNotFound,
    SessionNotFound,
)
from .domain.session import Session
from .domain.value_objects import (
    AssuranceLevel,
    AuthenticationMethod,
    CredentialId,
    CredentialType,
    SessionId,
)
from .ports import CredentialRepository, SessionRepository


class AuthenticationApplicationService:
    """Coordinates credential/session lifecycle around active Identities."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        credential_repository: CredentialRepository,
        session_repository: SessionRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._identities = identity_repository
        self._credentials = credential_repository
        self._sessions = session_repository
        self._clock = clock
        self._events = event_sink

    def register_credential(
        self,
        *,
        identity_id: IdentityId,
        credential_type: CredentialType,
        reference: str,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        fingerprint: str | None = None,
        label: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Credential:
        self._require_active_identity(identity_id)
        normalized_reference = reference.strip()
        if self._credentials.find_by_reference(normalized_reference) is not None:
            raise CredentialAlreadyExists(normalized_reference)
        now = self._clock.now()
        credential = Credential.create(
            identity_id=identity_id,
            credential_type=credential_type,
            reference=normalized_reference,
            created_at=now,
            valid_from=valid_from,
            valid_until=valid_until,
            fingerprint=fingerprint,
            label=label,
            metadata=metadata,
        )
        return self._save_credential(credential)

    def revoke_credential(self, credential_id: CredentialId) -> Credential:
        credential = self._require_credential(credential_id)
        credential.revoke(at=self._clock.now())
        return self._save_credential(credential)

    def expire_credential(self, credential_id: CredentialId) -> Credential:
        credential = self._require_credential(credential_id)
        credential.expire(at=self._clock.now())
        return self._save_credential(credential)

    def active_credentials(self, identity_id: IdentityId) -> tuple[Credential, ...]:
        return self._credentials.find_active_for_identity(identity_id, self._clock.now())

    def open_session(
        self,
        *,
        identity_id: IdentityId,
        method: AuthenticationMethod,
        assurance_level: AssuranceLevel,
        mfa: bool,
        expires_at: datetime,
        authenticated_at: datetime | None = None,
        provider_id: str | None = None,
        device_id: str | None = None,
        network_zone: str | None = None,
    ) -> Session:
        self._require_active_identity(identity_id)
        now = self._clock.now()
        context = AuthenticationContext(
            method=method,
            assurance_level=assurance_level,
            mfa=mfa,
            authenticated_at=now if authenticated_at is None else authenticated_at,
            provider_id=provider_id,
            device_id=device_id,
            network_zone=network_zone,
        )
        session = Session.open(
            identity_id=identity_id,
            context=context,
            created_at=now,
            expires_at=expires_at,
        )
        return self._save_session(session)

    def touch_session(self, session_id: SessionId) -> Session:
        session = self._require_session(session_id)
        session.touch(at=self._clock.now())
        return self._save_session(session)

    def revoke_session(self, session_id: SessionId, *, reason: str | None = None) -> Session:
        session = self._require_session(session_id)
        session.revoke(at=self._clock.now(), reason=reason)
        return self._save_session(session)

    def expire_session(self, session_id: SessionId) -> Session:
        session = self._require_session(session_id)
        session.expire(at=self._clock.now())
        return self._save_session(session)

    def revoke_all_sessions(
        self,
        identity_id: IdentityId,
        *,
        reason: str | None = None,
    ) -> tuple[Session, ...]:
        now = self._clock.now()
        revoked: list[Session] = []
        for session in self._sessions.find_active_for_identity(identity_id, now):
            session.revoke(at=now, reason=reason)
            revoked.append(self._save_session(session))
        return tuple(revoked)

    def active_sessions(self, identity_id: IdentityId) -> tuple[Session, ...]:
        return self._sessions.find_active_for_identity(identity_id, self._clock.now())

    def _require_active_identity(self, identity_id: IdentityId) -> None:
        identity = self._identities.get(identity_id)
        if identity is None:
            raise IdentityNotFound(identity_id)
        if identity.status is not IdentityStatus.ACTIVE:
            raise AuthenticationSubjectInactive(identity_id)

    def _require_credential(self, credential_id: CredentialId) -> Credential:
        credential = self._credentials.get(credential_id)
        if credential is None:
            raise CredentialNotFound(credential_id)
        return credential

    def _require_session(self, session_id: SessionId) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound(session_id)
        return session

    def _save_credential(self, credential: Credential) -> Credential:
        events = credential.pull_events()
        self._credentials.save(credential)
        self._events.publish(events)
        saved = self._credentials.get(credential.id)
        if saved is None:
            raise RuntimeError("Credential repository did not return persisted aggregate.")
        return saved

    def _save_session(self, session: Session) -> Session:
        events = session.pull_events()
        self._sessions.save(session)
        self._events.publish(events)
        saved = self._sessions.get(session.id)
        if saved is None:
            raise RuntimeError("Session repository did not return persisted aggregate.")
        return saved
