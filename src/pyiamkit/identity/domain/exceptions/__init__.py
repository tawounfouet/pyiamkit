"""Identity domain exceptions."""

from .identity_errors import (
    ExternalIdentityAlreadyLinked,
    ExternalIdentityLinkNotFound,
    IdentityError,
    IdentityNotFound,
    InvalidDisplayName,
    InvalidEmailAddress,
    InvalidExternalIdentity,
    InvalidIdentityTransition,
    InvalidServiceAccount,
)

__all__ = [
    "ExternalIdentityAlreadyLinked",
    "ExternalIdentityLinkNotFound",
    "IdentityError",
    "IdentityNotFound",
    "InvalidDisplayName",
    "InvalidEmailAddress",
    "InvalidExternalIdentity",
    "InvalidIdentityTransition",
    "InvalidServiceAccount",
]
