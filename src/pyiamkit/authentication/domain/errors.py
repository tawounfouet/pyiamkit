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
