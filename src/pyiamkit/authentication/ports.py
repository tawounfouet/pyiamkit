"""Authentication persistence ports."""

from datetime import datetime
from typing import Protocol

from pyiamkit.identity import IdentityId

from .domain.credential import Credential
from .domain.session import Session
from .domain.value_objects import CredentialId, SessionId
from .tokens import AccessTokenClaims, IssuedAccessToken


class CredentialRepository(Protocol):
    def get(self, credential_id: CredentialId) -> Credential | None: ...
    def save(self, credential: Credential) -> None: ...
    def find_by_reference(self, reference: str) -> Credential | None: ...
    def find_for_identity(self, identity_id: IdentityId) -> tuple[Credential, ...]: ...
    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Credential, ...]: ...


class SessionRepository(Protocol):
    def get(self, session_id: SessionId) -> Session | None: ...
    def save(self, session: Session) -> None: ...
    def find_for_identity(self, identity_id: IdentityId) -> tuple[Session, ...]: ...
    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Session, ...]: ...


class TokenProvider(Protocol):
    """Issue and verify authentication access tokens."""

    def issue_access_token(self, session: Session) -> IssuedAccessToken: ...
    def verify_access_token(self, token: str) -> AccessTokenClaims: ...
