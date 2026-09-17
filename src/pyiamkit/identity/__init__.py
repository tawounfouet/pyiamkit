"""Public alpha API for the Identity bounded context."""

from .application.service import IdentityApplicationService
from .domain.aggregates.identity import Identity
from .domain.entities.service_account import ServiceAccount
from .domain.entities.user import User
from .domain.exceptions.identity_errors import (
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
from .domain.value_objects.email_address import EmailAddress
from .domain.value_objects.identity_id import IdentityId
from .domain.value_objects.identity_status import IdentityStatus
from .domain.value_objects.identity_type import IdentityType
from .ports.repositories import IdentityRepository

__all__ = [
    "EmailAddress",
    "ExternalIdentityAlreadyLinked",
    "ExternalIdentityLinkNotFound",
    "Identity",
    "IdentityApplicationService",
    "IdentityError",
    "IdentityId",
    "IdentityNotFound",
    "IdentityRepository",
    "IdentityStatus",
    "IdentityType",
    "InvalidDisplayName",
    "InvalidEmailAddress",
    "InvalidExternalIdentity",
    "InvalidIdentityTransition",
    "InvalidServiceAccount",
    "ServiceAccount",
    "User",
]
