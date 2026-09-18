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
    InvalidMfaFactor,
    InvalidMfaFactorTransition,
    InvalidSession,
    InvalidSessionTransition,
    MfaFactorNotFound,
    MfaFactorOwnershipMismatch,
    MfaReplayDetected,
    MfaSecretUnavailable,
    MfaVerificationFailed,
    SessionNotFound,
)
from .mfa_factor import MfaFactor
from .session import Session
from .value_objects import (
    AssuranceLevel,
    AuthenticationMethod,
    CredentialId,
    CredentialStatus,
    CredentialType,
    MfaFactorId,
    MfaFactorStatus,
    MfaFactorType,
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
    "InvalidMfaFactor",
    "InvalidMfaFactorTransition",
    "InvalidSession",
    "InvalidSessionTransition",
    "MfaFactor",
    "MfaFactorId",
    "MfaFactorNotFound",
    "MfaFactorOwnershipMismatch",
    "MfaFactorStatus",
    "MfaFactorType",
    "MfaReplayDetected",
    "MfaSecretUnavailable",
    "MfaVerificationFailed",
    "Session",
    "SessionId",
    "SessionNotFound",
    "SessionStatus",
]
