"""In-memory reference adapters for Authentication persistence ports."""

from datetime import datetime

from pyiamkit.identity import IdentityId

from ..domain.credential import Credential
from ..domain.mfa_factor import MfaFactor
from ..domain.session import Session
from ..domain.value_objects import (
    CredentialId,
    MfaFactorId,
    MfaFactorStatus,
    SessionId,
)


class InMemoryCredentialRepository:
    def __init__(self) -> None:
        self._items: dict[CredentialId, Credential] = {}

    def get(self, credential_id: CredentialId) -> Credential | None:
        credential = self._items.get(credential_id)
        return None if credential is None else self._copy(credential)

    def save(self, credential: Credential) -> None:
        self._items[credential.id] = self._copy(credential)

    def find_by_reference(self, reference: str) -> Credential | None:
        normalized = reference.strip()
        for credential in self._items.values():
            if credential.reference == normalized:
                return self._copy(credential)
        return None

    def find_for_identity(self, identity_id: IdentityId) -> tuple[Credential, ...]:
        return tuple(
            self._copy(credential)
            for credential in sorted(self._items.values(), key=lambda item: str(item.id))
            if credential.identity_id == identity_id
        )

    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Credential, ...]:
        return tuple(
            credential
            for credential in self.find_for_identity(identity_id)
            if credential.is_active(at=at)
        )

    @staticmethod
    def _copy(credential: Credential) -> Credential:
        return Credential._rehydrate(
            credential_id=credential.id,
            version=credential.version,
            identity_id=credential.identity_id,
            credential_type=credential.type,
            status=credential.status,
            reference=credential.reference,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
            valid_from=credential.valid_from,
            valid_until=credential.valid_until,
            fingerprint=credential.fingerprint,
            label=credential.label,
            revoked_at=credential.revoked_at,
            metadata=credential.metadata,
        )


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._items: dict[SessionId, Session] = {}

    def get(self, session_id: SessionId) -> Session | None:
        session = self._items.get(session_id)
        return None if session is None else self._copy(session)

    def save(self, session: Session) -> None:
        self._items[session.id] = self._copy(session)

    def find_for_identity(self, identity_id: IdentityId) -> tuple[Session, ...]:
        return tuple(
            self._copy(session)
            for session in sorted(self._items.values(), key=lambda item: str(item.id))
            if session.identity_id == identity_id
        )

    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Session, ...]:
        return tuple(
            session for session in self.find_for_identity(identity_id) if session.is_active(at=at)
        )

    @staticmethod
    def _copy(session: Session) -> Session:
        return Session._rehydrate(
            session_id=session.id,
            version=session.version,
            identity_id=session.identity_id,
            status=session.status,
            context=session.context,
            created_at=session.created_at,
            updated_at=session.updated_at,
            expires_at=session.expires_at,
            last_activity_at=session.last_activity_at,
            revoked_at=session.revoked_at,
            revocation_reason=session.revocation_reason,
        )


class InMemoryMfaFactorRepository:
    def __init__(self) -> None:
        self._items: dict[MfaFactorId, MfaFactor] = {}

    def get(self, factor_id: MfaFactorId) -> MfaFactor | None:
        factor = self._items.get(factor_id)
        return None if factor is None else self._copy(factor)

    def save(self, factor: MfaFactor) -> None:
        self._items[factor.id] = self._copy(factor)

    def find_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        return tuple(
            self._copy(factor)
            for factor in sorted(self._items.values(), key=lambda item: str(item.id))
            if factor.identity_id == identity_id
        )

    def find_active_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        return tuple(
            factor
            for factor in self.find_for_identity(identity_id)
            if factor.status is MfaFactorStatus.ACTIVE
        )

    @staticmethod
    def _copy(factor: MfaFactor) -> MfaFactor:
        return MfaFactor._rehydrate(
            factor_id=factor.id,
            version=factor.version,
            identity_id=factor.identity_id,
            factor_type=factor.type,
            status=factor.status,
            secret_reference=factor.secret_reference,
            label=factor.label,
            created_at=factor.created_at,
            updated_at=factor.updated_at,
            activated_at=factor.activated_at,
            revoked_at=factor.revoked_at,
            last_verified_at=factor.last_verified_at,
            last_accepted_counter=factor.last_accepted_counter,
        )
