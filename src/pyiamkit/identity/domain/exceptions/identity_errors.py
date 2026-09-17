"""Identity-specific domain errors."""

from typing import ClassVar

from pyiamkit.shared import DomainError


class IdentityError(DomainError):
    code: ClassVar[str] = "IDENTITY_ERROR"


class IdentityNotFound(IdentityError):
    code = "IDENTITY_NOT_FOUND"

    def __init__(self, identity_id: object) -> None:
        super().__init__(f"Identity {identity_id} was not found.")


class InvalidIdentityTransition(IdentityError):
    code = "IDENTITY_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} identity from {current_status} status.")


class InvalidDisplayName(IdentityError):
    code = "IDENTITY_INVALID_DISPLAY_NAME"

    def __init__(self) -> None:
        super().__init__("Display name must contain between 1 and 255 characters.")


class InvalidEmailAddress(IdentityError):
    code = "IDENTITY_INVALID_EMAIL"

    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid email address: {value!r}.")


class InvalidServiceAccount(IdentityError):
    code = "IDENTITY_INVALID_SERVICE_ACCOUNT"


class InvalidExternalIdentity(IdentityError):
    code = "IDENTITY_INVALID_EXTERNAL_IDENTITY"


class ExternalIdentityAlreadyLinked(IdentityError):
    code = "IDENTITY_EXTERNAL_LINK_EXISTS"

    def __init__(self, provider_id: str, external_subject: str) -> None:
        super().__init__(f"External identity {provider_id}:{external_subject} is already linked.")


class ExternalIdentityLinkNotFound(IdentityError):
    code = "IDENTITY_EXTERNAL_LINK_NOT_FOUND"

    def __init__(self, provider_id: str, external_subject: str) -> None:
        super().__init__(f"External identity {provider_id}:{external_subject} is not linked.")
