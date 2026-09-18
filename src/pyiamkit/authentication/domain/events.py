"""Authentication domain event names."""

from enum import StrEnum


class AuthenticationEventType(StrEnum):
    CREDENTIAL_CREATED = "CredentialCreated"
    CREDENTIAL_REVOKED = "CredentialRevoked"
    CREDENTIAL_EXPIRED = "CredentialExpired"
    SESSION_OPENED = "SessionOpened"
    SESSION_TOUCHED = "SessionTouched"
    SESSION_REVOKED = "SessionRevoked"
    SESSION_EXPIRED = "SessionExpired"
    SESSION_STEPPED_UP = "SessionSteppedUp"
    MFA_FACTOR_CREATED = "MfaFactorCreated"
    MFA_FACTOR_ACTIVATED = "MfaFactorActivated"
    MFA_FACTOR_VERIFIED = "MfaFactorVerified"
    MFA_FACTOR_REVOKED = "MfaFactorRevoked"
