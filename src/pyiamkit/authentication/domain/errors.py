"""Authentication domain errors."""

from typing import ClassVar

from pyiamkit.shared import DomainError


class AuthenticationError(DomainError):
    code: ClassVar[str] = "AUTHENTICATION_ERROR"


class InvalidCredential(AuthenticationError):
    code = "CREDENTIAL_INVALID"


class InvalidCredentialTransition(AuthenticationError):
    code = "CREDENTIAL_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} credential from {current_status} status.")


class CredentialNotFound(AuthenticationError):
    code = "CREDENTIAL_NOT_FOUND"

    def __init__(self, credential_id: object) -> None:
        super().__init__(f"Credential {credential_id} was not found.")


class CredentialAlreadyExists(AuthenticationError):
    code = "CREDENTIAL_ALREADY_EXISTS"

    def __init__(self, reference: str) -> None:
        super().__init__(f"Credential reference {reference!r} already exists.")


class InvalidSession(AuthenticationError):
    code = "SESSION_INVALID"


class InvalidSessionTransition(AuthenticationError):
    code = "SESSION_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} session from {current_status} status.")


class SessionNotFound(AuthenticationError):
    code = "SESSION_NOT_FOUND"

    def __init__(self, session_id: object) -> None:
        super().__init__(f"Session {session_id} was not found.")


class AuthenticationSubjectInactive(AuthenticationError):
    code = "AUTHENTICATION_SUBJECT_INACTIVE"

    def __init__(self, identity_id: object) -> None:
        super().__init__(f"Identity {identity_id} is not active for authentication.")


class InvalidMfaFactor(AuthenticationError):
    code = "MFA_FACTOR_INVALID"


class InvalidMfaFactorTransition(AuthenticationError):
    code = "MFA_FACTOR_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} MFA factor from {current_status} status.")


class MfaFactorNotFound(AuthenticationError):
    code = "MFA_FACTOR_NOT_FOUND"

    def __init__(self, factor_id: object) -> None:
        super().__init__(f"MFA factor {factor_id} was not found.")


class MfaFactorOwnershipMismatch(AuthenticationError):
    code = "MFA_FACTOR_OWNERSHIP_MISMATCH"

    def __init__(self, factor_id: object, identity_id: object) -> None:
        super().__init__(f"MFA factor {factor_id} does not belong to Identity {identity_id}.")


class MfaVerificationFailed(AuthenticationError):
    code = "MFA_VERIFICATION_FAILED"


class MfaReplayDetected(AuthenticationError):
    code = "MFA_REPLAY_DETECTED"

    def __init__(self, factor_id: object) -> None:
        super().__init__(f"An already accepted MFA code was replayed for factor {factor_id}.")


class MfaSecretUnavailable(AuthenticationError):
    code = "MFA_SECRET_UNAVAILABLE"

    def __init__(self, reference: str) -> None:
        super().__init__(f"MFA secret reference {reference!r} is unavailable.")
