"""Authentication domain contracts."""

from .context import AuthenticationContext
from .credential import Credential
from .errors import (
    AuthenticationError,
    AuthenticationSubjectInactive,
    CredentialAlreadyExists,
    CredentialNotFound,
    InvalidCredential,
    InvalidCredentialTransition,
    InvalidSession,
    InvalidSessionTransition,
    SessionNotFound,
)
from .session import Session
from .value_objects import (
    AssuranceLevel,
    AuthenticationMethod,
    CredentialId,
    CredentialStatus,
    CredentialType,
    SessionId,
    SessionStatus,
)

__all__ = [
    "AssuranceLevel",
    "AuthenticationContext",
    "AuthenticationError",
    "AuthenticationMethod",
    "AuthenticationSubjectInactive",
    "Credential",
    "CredentialAlreadyExists",
    "CredentialId",
    "CredentialNotFound",
    "CredentialStatus",
    "CredentialType",
    "InvalidCredential",
    "InvalidCredentialTransition",
    "InvalidSession",
    "InvalidSessionTransition",
    "Session",
    "SessionId",
    "SessionNotFound",
    "SessionStatus",
]
